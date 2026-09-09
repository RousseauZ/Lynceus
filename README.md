# Lynceus
Lynceus, the Argonaut, who could see across impossible distances, through walls even through the earth itself. He was the one who spotted what nobody else could from nobody else stood.

An offsite watchdog for a homelab. A computer at a remote location connects home over WireGuard, checks whether the hosts and services are alive, and reports the result to Home Assistant and a to a web hook.

## Why 
Monitoring that runs inside the thing it monitors cannot report its own death. When power fail, the uplink drops or an hypervisor locks up, the dashboard does not turn red, it stops. 
Lynceus solves that by watching from outside the failure drain. It lives on different hardware, on a different power circuit, behind a different internet connection. If home goes out, Lynceus is the thing still standing to tell you it failed.
It is deliberately small. It does not collect metrics, it does not store history, and it does not try to tell you why something is down. It answers  one question, is it reachable?

#### Every cycle Lynceus performs three separate checks in order;

1. Publishes its own availability. Im plemented as an MQTT "last will". So the broker marks Lynceus offline the moment it disappears

2. Verifies the WireGuard peer is up and the handshake is recent. Without this, a dead tunnel and a dead lab will look the same.

3. Probes each configured host. Each larget gets its own state, so "one service is down" never turns into "everything is down".

Each result is published over MQTT and picked up by Home Assistant through MQTT discovery. Failures will also trigger a web hook notification, with a configurable number of consecutive failures required before alerting so that a single dropped packet does not wake anyone up.

