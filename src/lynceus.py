"""
Lynceus — offsite monitor.

Checks two layers:
  1. The WireGuard handshake, which tells us whether the connection to the
     home network is alive at all.
  2. ICMP or TCP checks on individual hosts, through the tunnel.

If the handshake is stale the host checks are skipped, because everything
would report down for a single underlying cause.

On startup it reports how long it was away and what changed while it was
gone, so a power cut at the monitor's own location does not pass silently.

Alerts go to a Discord webhook. Status is optionally mirrored to MQTT for
Home Assistant. MQTT is deliberately optional and never blocks alerting:
Discord has to keep working when the broker does not.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from types import FrameType

try:
    import paho.mqtt.client as mqtt

    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

LOG = logging.getLogger("lynceus")
STOP = threading.Event()

CONFIG_PATH = Path(os.environ.get("LYNCEUS_CONFIG", "/etc/lynceus/config.yaml"))
HOSTS_PATH = Path(os.environ.get("LYNCEUS_HOSTS", "/etc/lynceus/hosts.yaml"))

# `wg show <if> latest-handshakes` prints "<peer-key> <unix-timestamp>" per peer.
WG_HANDSHAKE_FIELDS = 2

# Discord rate-limits aggressively; back off and retry rather than drop an alert.
DISCORD_MAX_ATTEMPTS = 3
HTTP_TOO_MANY_REQUESTS = 429

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------


@dataclass
class Host:
    """A single monitored host, loaded from hosts.yaml."""

    name: str
    address: str
    check: str = "icmp"
    port: int | None = None
    timeout: float = 3.0
    enabled: bool = True
    note: str = ""

    # Runtime state
    up: bool | None = field(default=None, init=False)
    consecutive_failures: int = field(default=0, init=False)
    down_since: float | None = field(default=None, init=False)
    last_reminder: float | None = field(default=None, init=False)

    def probe(self) -> bool:
        """Run one check. Returns True if the host answered."""
        if self.check == "tcp":
            return self._probe_tcp()
        return self._probe_icmp()

    def _probe_icmp(self) -> bool:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(max(1, self.timeout))), self.address],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 2,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        else:
            return result.returncode == 0

    def _probe_tcp(self) -> bool:
        if not self.port:
            LOG.error("host %r uses tcp but has no port configured", self.name)
            return False
        try:
            with socket.create_connection((self.address, self.port), timeout=self.timeout):
                return True
        except OSError:
            return False


# --------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------


def handshake_age(interface: str) -> float | None:
    """
    Return seconds since the most recent WireGuard handshake on this interface.

    Returns None when the interface is missing or has never handshaked.
    Requires root, because `wg show` reads a privileged netlink interface.
    """
    try:
        result = subprocess.run(
            ["wg", "show", interface, "latest-handshakes"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        LOG.exception("could not run wg show")
        return None

    if result.returncode != 0:
        LOG.error("wg show failed: %s", result.stderr.strip())
        return None

    newest = 0
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= WG_HANDSHAKE_FIELDS and parts[1].isdigit():
            newest = max(newest, int(parts[1]))

    if newest == 0:
        return None

    return time.time() - newest


def nudge_tunnel(target: str) -> None:
    """
    Send a single packet through the tunnel to trigger a handshake.

    WireGuard is silent until there is traffic, so without this a healthy
    tunnel can look stale simply because nothing has been sent recently.
    """
    subprocess.run(
        ["ping", "-c", "1", "-W", "2", target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


# --------------------------------------------------------------------------
# Local hardware
# --------------------------------------------------------------------------


def cpu_temperature() -> float | None:
    """Return the CPU temperature in degrees Celsius, or None if unavailable."""
    try:
        raw = Path("/sys/class/thermal/thermal_zone0/temp").read_text(encoding="utf-8").strip()
        return round(int(raw) / 1000, 1)
    except (OSError, ValueError):
        return None


def throttle_flags() -> dict[str, bool] | None:
    """
    Read the Raspberry Pi throttling bitmask.

    Bit 0  : undervoltage right now
    Bit 1  : ARM frequency capped right now
    Bit 2  : throttled right now
    Bit 16 : undervoltage has occurred since boot
    Bit 18 : throttling has occurred since boot

    The "since boot" bits matter most for an unattended machine: a marginal
    power supply shows up there long before it causes visible trouble.
    """
    try:
        result = subprocess.run(
            ["vcgencmd", "get_throttled"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None

    match = re.search(r"0x([0-9a-fA-F]+)", result.stdout)
    if not match:
        return None

    value = int(match.group(1), 16)
    return {
        "undervoltage_now": bool(value & 0x1),
        "throttled_now": bool(value & 0x4),
        "undervoltage_since_boot": bool(value & 0x10000),
        "throttled_since_boot": bool(value & 0x40000),
    }


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


class Discord:
    """Sends embed messages to a Discord webhook, with retries on rate limits."""

    COLOUR_DOWN = 0xE74C3C
    COLOUR_UP = 0x2ECC71
    COLOUR_INFO = 0x3498DB

    def __init__(self, webhook_url: str, username: str = "Lynceus") -> None:
        """Store the webhook, rejecting anything that is not an https:// url."""
        if webhook_url and not webhook_url.startswith("https://"):
            msg = "discord webhook_url must be an https:// url"
            raise ValueError(msg)
        self.webhook_url = webhook_url
        self.username = username

    def send(self, title: str, description: str, colour: int) -> None:
        """Post one embed, retrying on rate limits and transient network errors."""
        if not self.webhook_url:
            LOG.warning("no webhook configured, message dropped: %s", title)
            return

        payload = {
            "username": self.username,
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "color": colour,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            ],
        }

        # S310: the scheme is pinned to https:// in __init__, so this cannot be
        # talked into opening file: or a custom scheme.
        request = urllib.request.Request(  # noqa: S310
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "lynceus-monitor/1.0",
            },
            method="POST",
        )

        for attempt in range(DISCORD_MAX_ATTEMPTS):
            try:
                with urllib.request.urlopen(request, timeout=10):  # noqa: S310
                    return
            except urllib.error.HTTPError as exc:
                if exc.code == HTTP_TOO_MANY_REQUESTS and attempt < DISCORD_MAX_ATTEMPTS - 1:
                    time.sleep(5 * (attempt + 1))
                    continue
                LOG.exception("discord rejected the message")
                return
            except (urllib.error.URLError, OSError):
                LOG.exception("could not reach discord (attempt %d)", attempt + 1)
                if attempt < DISCORD_MAX_ATTEMPTS - 1:
                    time.sleep(5)

    def down(self, title: str, description: str) -> None:
        """Send a message in the "something is broken" colour."""
        self.send(title, description, self.COLOUR_DOWN)

    def up(self, title: str, description: str) -> None:
        """Send a message in the "recovered" colour."""
        self.send(title, description, self.COLOUR_UP)

    def info(self, title: str, description: str) -> None:
        """Send a neutral, informational message."""
        self.send(title, description, self.COLOUR_INFO)


# --------------------------------------------------------------------------
# MQTT / Home Assistant
# --------------------------------------------------------------------------


class MqttPublisher:
    """
    Mirrors the monitor's own health to Home Assistant.

    This publishes entities describing the monitor, not the hosts it watches —
    those are already covered by Discord alerts. The point here is the other
    half of the failover: if this Pi dies, Home Assistant notices the
    availability topic go stale and can tell you.

    Every failure is swallowed and logged. A broken broker must never stop the
    checks or the Discord alerts. That is why the handlers below catch Exception
    broadly: paho raises a wide range of errors depending on the transport, and
    none of them may be fatal here.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        """Read the mqtt section of the config and prepare the client."""
        self.enabled = bool(config.get("enabled", False)) and bool(config.get("host"))
        if not self.enabled:
            return

        if not MQTT_AVAILABLE:
            LOG.error("mqtt enabled but paho-mqtt is not installed, disabling")
            self.enabled = False
            return

        self.host: str = config["host"]
        self.port: int = int(config.get("port", 1883))
        self.username: str | None = config.get("username")
        self.password: str | None = config.get("password")
        self.base: str = config.get("base_topic", "lynceus").rstrip("/")
        self.discovery: str = config.get("discovery_prefix", "homeassistant").rstrip("/")
        self.node: str = config.get("node_id", "lynceus")

        self.availability_topic = f"{self.base}/availability"
        self.state_topic = f"{self.base}/state"
        self.connected = False
        self.discovery_sent = False

        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"lynceus-{socket.gethostname()}",
        )
        if self.username:
            self.client.username_pw_set(self.username, self.password)

        # If this Pi drops off, Home Assistant sees it within seconds
        self.client.will_set(self.availability_topic, "offline", qos=1, retain=True)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect

    def start(self) -> None:
        """Connect to the broker in the background, disabling mqtt if it fails."""
        if not self.enabled:
            return
        try:
            self.client.connect_async(self.host, self.port, keepalive=60)
            self.client.loop_start()
            LOG.info("mqtt: connecting to %s:%s", self.host, self.port)
        except Exception:
            LOG.exception("mqtt: could not start client")
            self.enabled = False

    def _on_connect(
        self,
        client: Any,  # noqa: ANN401 - paho hands us its own client type
        _userdata: object,
        _flags: object,
        reason_code: object,
        _properties: object = None,
    ) -> None:
        if reason_code == 0:
            self.connected = True
            LOG.info("mqtt: connected")
            client.publish(self.availability_topic, "online", qos=1, retain=True)
            self.publish_discovery()
        else:
            LOG.error("mqtt: connection refused (%s)", reason_code)

    def _on_disconnect(
        self,
        _client: object,
        _userdata: object,
        _flags: object,
        reason_code: object,
        _properties: object = None,
    ) -> None:
        self.connected = False
        if not STOP.is_set():
            LOG.warning("mqtt: disconnected (%s), will retry", reason_code)

    # --- Discovery --------------------------------------------------------

    def _device(self) -> dict[str, Any]:
        return {
            "identifiers": [self.node],
            "name": "Lynceus monitor",
            "manufacturer": "Self-built",
            "model": "Offsite monitor",
        }

    def _entity(self, component: str, key: str, config: dict[str, Any]) -> None:
        config.setdefault("availability_topic", self.availability_topic)
        config.setdefault("state_topic", self.state_topic)
        config["unique_id"] = f"{self.node}_{key}"
        config["object_id"] = f"{self.node}_{key}"
        config["device"] = self._device()

        topic = f"{self.discovery}/{component}/{self.node}/{key}/config"
        self.client.publish(topic, json.dumps(config), qos=1, retain=True)

    def publish_discovery(self) -> None:
        """Announce the entities so Home Assistant creates them by itself."""
        try:
            self._entity(
                "sensor",
                "hosts_up",
                {
                    "name": "Hosts up",
                    "value_template": "{{ value_json.hosts_up }}",
                    "state_class": "measurement",
                    "icon": "mdi:server-network",
                },
            )

            self._entity(
                "sensor",
                "hosts_down",
                {
                    "name": "Hosts down",
                    "value_template": "{{ value_json.hosts_down_names }}",
                    "icon": "mdi:server-network-off",
                },
            )

            self._entity(
                "sensor",
                "temperature",
                {
                    "name": "CPU temperature",
                    "value_template": "{{ value_json.cpu_temperature }}",
                    "unit_of_measurement": "°C",
                    "device_class": "temperature",
                    "state_class": "measurement",
                },
            )

            self._entity(
                "binary_sensor",
                "undervoltage",
                {
                    "name": "Undervoltage",
                    "value_template": "{{ value_json.undervoltage_since_boot }}",
                    "payload_on": "True",
                    "payload_off": "False",
                    "device_class": "problem",
                },
            )

            self._entity(
                "sensor",
                "last_check",
                {
                    "name": "Last check",
                    "value_template": "{{ value_json.last_check }}",
                    "device_class": "timestamp",
                },
            )

            self.discovery_sent = True
            LOG.info("mqtt: discovery published")
        except Exception:
            LOG.exception("mqtt: could not publish discovery")

    # --- State ------------------------------------------------------------

    def publish_state(self, payload: dict[str, Any]) -> None:
        """Publish the current monitor state, if the broker is connected."""
        if not self.enabled or not self.connected:
            return
        try:
            self.client.publish(self.state_topic, json.dumps(payload), qos=0, retain=True)
        except Exception:
            LOG.exception("mqtt: could not publish state")

    def shutdown(self) -> None:
        """Mark the monitor offline and close the connection cleanly."""
        if not self.enabled:
            return
        try:
            self.client.publish(self.availability_topic, "offline", qos=1, retain=True)
            time.sleep(0.3)
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            LOG.debug("mqtt: error while shutting down", exc_info=True)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def humanize(seconds: float) -> str:
    """Turn a duration into something readable in a chat message."""
    total = int(seconds)
    if total < SECONDS_PER_MINUTE:
        return f"{total}s"
    if total < SECONDS_PER_HOUR:
        return f"{total // SECONDS_PER_MINUTE}m"
    if total < SECONDS_PER_DAY:
        minutes = (total % SECONDS_PER_HOUR) // SECONDS_PER_MINUTE
        return f"{total // SECONDS_PER_HOUR}h {minutes}m"
    hours = (total % SECONDS_PER_DAY) // SECONDS_PER_HOUR
    return f"{total // SECONDS_PER_DAY}d {hours}h"


def local_time(epoch: float) -> str:
    """Format an epoch timestamp in the machine's local timezone."""
    # Parsed as UTC and then converted, so the timezone is explicit rather
    # than implied by the process environment.
    return datetime.fromtimestamp(epoch, tz=UTC).astimezone().strftime("%d %b %H:%M")


# --------------------------------------------------------------------------
# Monitor
# --------------------------------------------------------------------------


class Monitor:
    """Owns the check loop, the alerting decisions, and the persisted state."""

    def __init__(self, config: dict[str, Any], hosts: list[Host]) -> None:
        """Build a monitor from the parsed config and host list."""
        general = config.get("general", {})
        self.interval: int = int(general.get("interval", 60))
        self.threshold: int = int(general.get("failure_threshold", 3))
        self.reminder_seconds: int = int(general.get("reminder_hours", 6)) * SECONDS_PER_HOUR

        # A gap larger than this counts as "the monitor was away" rather than
        # a quick service restart. Defaults to four missed cycles.
        self.gap_threshold: int = int(general.get("startup_gap_threshold", self.interval * 4))

        wg = config.get("wireguard", {})
        self.interface: str = wg.get("interface", "wg0")
        self.handshake_max_age: int = int(wg.get("handshake_max_age", 180))
        self.nudge_target: str | None = wg.get("nudge_target")

        discord_cfg = config.get("discord", {})
        self.discord = Discord(
            discord_cfg.get("webhook_url", ""),
            discord_cfg.get("username", "Lynceus"),
        )

        self.mqtt = MqttPublisher(config.get("mqtt", {}))

        self.state_file = Path(general.get("state_file", "/var/lib/lynceus/state.json"))

        self.hosts = [h for h in hosts if h.enabled]
        if not self.hosts:
            msg = "no enabled hosts found in hosts.yaml"
            raise ValueError(msg)

        # Tunnel state
        self.tunnel_up: bool | None = None
        self.tunnel_failures = 0
        self.tunnel_down_since: float | None = None
        self.tunnel_last_reminder: float | None = None

        # What the world looked like the last time we wrote state, used for
        # the startup report. Filled in by load_state().
        self.previous_seen: float | None = None
        self.previous_down: list[str] = []
        self.had_previous_state = False

        self.load_state()

    # --- Persistence ------------------------------------------------------

    def load_state(self) -> None:
        """Restore the previous state so a restart does not replay alerts."""
        if not self.state_file.is_file():
            LOG.info("no previous state found, starting fresh")
            return

        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            LOG.warning("could not read state file, starting fresh", exc_info=True)
            return

        self.had_previous_state = True

        self.previous_seen = data.get("last_seen")
        if self.previous_seen is None:
            updated = data.get("updated")
            if updated:
                try:
                    self.previous_seen = datetime.fromisoformat(updated).timestamp()
                except ValueError:
                    LOG.debug("state file has an unparseable 'updated' value")

        self.tunnel_up = data.get("tunnel_up")
        self.tunnel_down_since = data.get("tunnel_down_since")
        self.tunnel_last_reminder = data.get("tunnel_last_reminder")

        saved_hosts = data.get("hosts", {})
        for host in self.hosts:
            saved = saved_hosts.get(host.name)
            if not saved:
                continue
            host.up = saved.get("up")
            host.down_since = saved.get("down_since")
            host.last_reminder = saved.get("last_reminder")
            if saved.get("up") is False:
                self.previous_down.append(host.name)

        LOG.info("restored state from %s", self.state_file)

    def save_state(self) -> None:
        """Write the current state atomically, so a crash cannot corrupt it."""
        now = time.time()
        data = {
            "updated": datetime.now(UTC).isoformat(),
            "last_seen": now,
            "tunnel_up": self.tunnel_up,
            "tunnel_down_since": self.tunnel_down_since,
            "tunnel_last_reminder": self.tunnel_last_reminder,
            "hosts": {
                host.name: {
                    "up": host.up,
                    "down_since": host.down_since,
                    "last_reminder": host.last_reminder,
                }
                for host in self.hosts
            },
        }

        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temp file first so a crash mid-write cannot corrupt it
            temp = self.state_file.with_name(self.state_file.name + ".tmp")
            temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temp.replace(self.state_file)
        except OSError:
            LOG.exception("could not write state file")

    # --- Checks -----------------------------------------------------------

    def check_tunnel(self) -> bool:
        """Return True if the WireGuard handshake is recent enough."""
        if self.nudge_target:
            nudge_tunnel(self.nudge_target)

        age = handshake_age(self.interface)
        if age is None:
            LOG.debug("no handshake on %s", self.interface)
            return False

        LOG.debug("handshake age: %.0fs", age)
        return age <= self.handshake_max_age

    def run_cycle(self, *, silent: bool = False) -> None:
        """
        Run one full round of checks.

        With silent=True the results are recorded but no alerts are sent.
        Used on startup to establish a baseline.
        """
        now = time.time()
        self._update_tunnel(now, silent=silent)

        # No point checking hosts we cannot reach
        if self.tunnel_up is False:
            LOG.info("tunnel down, skipping host checks")
            self.publish_mqtt_state()
            self.save_state()
            return

        newly_down, newly_up = self._check_hosts(now)

        if not silent:
            self.report(newly_down, newly_up, now)

        status = ", ".join(f"{h.name}={'up' if h.up else 'DOWN'}" for h in self.hosts)
        LOG.debug(
            "cycle complete — tunnel=%s | %s",
            "up" if self.tunnel_up else "DOWN",
            status,
        )

        self.publish_mqtt_state()
        self.save_state()

    def _update_tunnel(self, now: float, *, silent: bool) -> None:
        """Probe the tunnel and update its verdict, alerting when it flips."""
        tunnel_ok = self.check_tunnel()

        if tunnel_ok:
            self.tunnel_failures = 0
        else:
            self.tunnel_failures += 1

        # Only change the tunnel verdict once we cross the threshold
        if not tunnel_ok and self.tunnel_failures >= self.threshold:
            if self.tunnel_up is not False:
                self.tunnel_up = False
                self.tunnel_down_since = now
                self.tunnel_last_reminder = now
                if not silent:
                    self.discord.down(
                        "No contact with home network",
                        f"The WireGuard handshake has been stale for more than "
                        f"{humanize(self.threshold * self.interval)}.\n\n"
                        f"This means the internet connection, the router, or the "
                        f"WireGuard host is unreachable. Individual host checks are "
                        f"paused until the tunnel returns.",
                    )
            elif not silent:
                self.maybe_remind_tunnel(now)
        elif tunnel_ok and self.tunnel_up is not True:
            was_down_for = now - self.tunnel_down_since if self.tunnel_down_since else 0
            self.tunnel_up = True
            self.tunnel_down_since = None
            self.tunnel_last_reminder = None
            if not silent and was_down_for:
                self.discord.up(
                    "Home network reachable again",
                    f"The tunnel is back up after {humanize(was_down_for)}.",
                )

    def _check_hosts(self, now: float) -> tuple[list[Host], list[tuple[Host, float]]]:
        """Probe every enabled host and return what changed this cycle."""
        newly_down: list[Host] = []
        newly_up: list[tuple[Host, float]] = []

        for host in self.hosts:
            reachable = host.probe()

            if reachable:
                host.consecutive_failures = 0
            else:
                host.consecutive_failures += 1

            if not reachable and host.consecutive_failures >= self.threshold:
                if host.up is not False:
                    host.up = False
                    host.down_since = now
                    host.last_reminder = now
                    newly_down.append(host)
                    LOG.warning("%s is down", host.name)
            elif reachable and host.up is not True:
                if host.down_since:
                    newly_up.append((host, now - host.down_since))
                    LOG.info("%s is back up", host.name)
                host.up = True
                host.down_since = None
                host.last_reminder = None

        return newly_down, newly_up

    # --- MQTT -------------------------------------------------------------

    def publish_mqtt_state(self) -> None:
        """Mirror the monitor's own health to the broker."""
        if not self.mqtt.enabled:
            return

        down_names = [h.name for h in self.hosts if h.up is False]
        flags = throttle_flags() or {}

        payload = {
            "tunnel_up": bool(self.tunnel_up),
            "hosts_total": len(self.hosts),
            "hosts_up": len(self.hosts) - len(down_names),
            "hosts_down": len(down_names),
            "hosts_down_names": ", ".join(down_names) if down_names else "none",
            "cpu_temperature": cpu_temperature(),
            "undervoltage_now": flags.get("undervoltage_now", False),
            "undervoltage_since_boot": flags.get("undervoltage_since_boot", False),
            "throttled_since_boot": flags.get("throttled_since_boot", False),
            "last_check": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self.mqtt.publish_state(payload)

    # --- Reporting --------------------------------------------------------

    def _gap_line(self, now: float) -> str:
        """Describe how long the monitor was away, as one line."""
        if self.previous_seen is None:
            if self.had_previous_state:
                return "Restarted, previous downtime unknown"
            return "First run, no previous state"

        gap = now - self.previous_seen
        if gap < 0:
            # The Pi has no battery-backed clock, so on boot the time can
            # briefly run ahead of reality until NTP corrects it.
            return "Restarted (clock had not synced yet, gap unknown)"
        if gap >= self.gap_threshold:
            return (
                f"**Monitor was offline for {humanize(gap)}** "
                f"(last check {local_time(self.previous_seen)})"
            )
        return f"Restarted after {humanize(gap)}"

    def _hardware_line(self) -> str | None:
        """Summarise local hardware health, or None if there is nothing to say."""
        temp = cpu_temperature()
        flags = throttle_flags() or {}
        hardware = []
        if temp is not None:
            hardware.append(f"{temp} °C")
        if flags.get("undervoltage_since_boot"):
            hardware.append("undervoltage detected")
        if flags.get("throttled_since_boot"):
            hardware.append("has been throttled")
        if not hardware:
            return None
        return f"**Pi:** {', '.join(hardware)}"

    def startup_report(self) -> None:
        """
        Send one message describing the gap and what changed across it.

        Sent after the silent baseline cycle, so it reflects the situation
        as it is right now rather than as it was before the monitor stopped.
        """
        now = time.time()
        currently_down = [h.name for h in self.hosts if h.up is False]
        up_count = len(self.hosts) - len(currently_down)

        lines: list[str] = [self._gap_line(now), ""]
        lines.append(f"**Tunnel:** {'up' if self.tunnel_up else 'DOWN'}")

        if self.previous_down:
            lines.append(f"**Was down before the gap:** {', '.join(self.previous_down)}")
        elif self.had_previous_state:
            lines.append("**Was down before the gap:** nothing")

        if currently_down:
            lines.append(f"**Down now:** {', '.join(currently_down)}")
        else:
            lines.append(f"**Down now:** nothing — {up_count}/{len(self.hosts)} up")

        recovered = [n for n in self.previous_down if n not in currently_down]
        if recovered:
            lines.append(f"**Recovered while offline:** {', '.join(recovered)}")

        newly = [n for n in currently_down if n not in self.previous_down]
        if newly and self.had_previous_state:
            lines.append(f"**Failed while offline:** {', '.join(newly)}")

        # Hardware health is worth knowing about right after a restart:
        # an unexpected reboot is often a power problem.
        hardware = self._hardware_line()
        if hardware:
            lines.append(hardware)

        colour = Discord.COLOUR_UP if not currently_down and self.tunnel_up else Discord.COLOUR_INFO

        self.discord.send("Monitor started", "\n".join(lines), colour)
        LOG.info("startup report sent")

    def report(
        self,
        newly_down: list[Host],
        newly_up: list[tuple[Host, float]],
        now: float,
    ) -> None:
        """Send alerts for hosts that changed state, then any due reminders."""
        if newly_down:
            lines = [
                f"• **{h.name}** ({h.address}){f' — {h.note}' if h.note else ''}"
                for h in newly_down
            ]
            self.discord.down(
                f"{len(newly_down)} host{'s' if len(newly_down) > 1 else ''} unreachable",
                "\n".join(lines) + "\n\nThe tunnel is up, so this is the host itself.",
            )

        if newly_up:
            lines = [
                f"• **{h.name}** — was down for {humanize(duration)}" for h, duration in newly_up
            ]
            self.discord.up(
                f"{len(newly_up)} host{'s' if len(newly_up) > 1 else ''} back online",
                "\n".join(lines),
            )

        self.maybe_remind_hosts(now)

    def maybe_remind_tunnel(self, now: float) -> None:
        """Re-alert about a still-unreachable tunnel, at most once per interval."""
        if self.tunnel_last_reminder is None:
            return
        if now - self.tunnel_last_reminder < self.reminder_seconds:
            return

        self.tunnel_last_reminder = now
        duration = now - self.tunnel_down_since if self.tunnel_down_since else 0
        self.discord.down(
            "Still no contact with home network",
            f"Unreachable for {humanize(duration)}.",
        )

    def maybe_remind_hosts(self, now: float) -> None:
        """Re-alert about hosts that have been down since the last reminder."""
        due = [
            host
            for host in self.hosts
            if host.up is False
            and host.last_reminder is not None
            and now - host.last_reminder >= self.reminder_seconds
        ]
        if not due:
            return

        for host in due:
            host.last_reminder = now

        lines = [
            f"• **{h.name}** — down for {humanize(now - h.down_since if h.down_since else 0)}"
            for h in due
        ]
        self.discord.down("Still unreachable", "\n".join(lines))

    # --- Main loop --------------------------------------------------------

    def run(self) -> None:
        """Establish a baseline, report it, then check on a fixed interval."""
        LOG.info(
            "starting: %d hosts, %ds interval, alert after %d failed checks",
            len(self.hosts),
            self.interval,
            self.threshold,
        )

        self.mqtt.start()

        # Establish a baseline without alerting, so a restart does not produce
        # a flood of individual messages. The startup report below covers what
        # changed in one go instead.
        LOG.info("running silent baseline cycle")
        self.run_cycle(silent=True)
        LOG.info("baseline established, alerts enabled")

        self.startup_report()

        while not STOP.is_set():
            started = time.monotonic()
            try:
                self.run_cycle()
            except Exception:
                LOG.exception("check cycle failed, continuing")

            elapsed = time.monotonic() - started
            if elapsed > self.interval:
                LOG.warning(
                    "cycle took %.1fs, longer than the %ds interval",
                    elapsed,
                    self.interval,
                )
            STOP.wait(max(0.0, self.interval - elapsed))

        LOG.info("shutting down")
        self.save_state()
        self.mqtt.shutdown()


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML mapping, exiting with a clear message if it is unusable."""
    if not path.is_file():
        LOG.error("file not found: %s", path)
        sys.exit(1)

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        LOG.exception("invalid YAML in %s", path)
        sys.exit(1)

    if not isinstance(data, dict):
        LOG.error("%s should contain a YAML mapping", path)
        sys.exit(1)

    return data


def load_hosts(path: Path) -> list[Host]:
    """Load and validate the host list, exiting on a malformed entry."""
    data = load_yaml(path)
    entries = data.get("hosts", [])

    if not isinstance(entries, list):
        LOG.error("'hosts' in %s should be a list", path)
        sys.exit(1)

    hosts: list[Host] = []
    seen: set[str] = set()

    for entry in entries:
        try:
            host = Host(**entry)
        except TypeError:
            LOG.exception("invalid host entry %r", entry)
            sys.exit(1)

        if host.name in seen:
            LOG.error("duplicate host name: %s", host.name)
            sys.exit(1)
        seen.add(host.name)
        hosts.append(host)

    LOG.info("loaded %d hosts from %s", len(hosts), path)
    return hosts


def handle_signal(signum: int, _frame: FrameType | None) -> None:
    """Ask the main loop to stop at the next opportunity."""
    LOG.info("received %s", signal.Signals(signum).name)
    STOP.set()


def main() -> int:
    """Configure logging, load the config, and run until told to stop."""
    logging.basicConfig(
        level=os.environ.get("LYNCEUS_LOGLEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    config = load_yaml(CONFIG_PATH)
    hosts = load_hosts(HOSTS_PATH)

    try:
        monitor = Monitor(config, hosts)
    except (TypeError, ValueError):
        LOG.exception("configuration error")
        return 1

    monitor.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
