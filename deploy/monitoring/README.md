# NIL control-plane monitoring (blackbox)

Uptime + latency alerting for the **Portal** and **Coordinator** control surfaces. This is
deliberately **blackbox**: Prometheus + `blackbox_exporter` probe the operator's own `/healthz`
endpoints and alert when they fail or slow. It observes only *liveness of your own services* —
**no user data, no per-connection data, no metrics endpoint on the apps** (they expose none).

## Privacy posture (why blackbox, and what is NOT monitored)
- **Nodes (data plane) are NOT monitored here.** They are logless/RAM-only by design (PD-2);
  probing them would create availability metadata about the tunnel path. Leave them out.
- **No whitebox `/metrics`.** Adding a metrics endpoint to the Portal/Coordinator would be a new
  data-collection surface that must first pass a PII review (PD-1). It is a deliberate follow-up,
  not shipped here. Blackbox `/healthz` probing collects nothing about users.
- The only thing this stack learns is "is my own control surface up, and how fast" — operator ops,
  not user surveillance.

## Deploy
1. Edit `prometheus.yml`: replace the two `targets` with your real Portal + Coordinator
   `/healthz` URLs (they sit behind Caddy/TLS).
2. Edit `alertmanager.yml`: fill in a real receiver (the webhook URL is a placeholder).
3. `docker compose -f compose.monitoring.yaml up -d` (on an ops host, NOT a node).
4. Pin every image by `@sha256:` digest before production (matches the repo's supply-chain
   discipline; the tags here are placeholders).

## Log rotation
Containers should cap their own logs at the Docker level (the correct mechanism — no host
logrotate needed). Add to each Portal/Coordinator service in your (private) compose file:

```yaml
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
```

Nodes keep no disk logs, so there is nothing to rotate there.
