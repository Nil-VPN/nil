# NIL control-plane monitoring (blackbox)

Uptime + latency alerting for the **Portal** and **Coordinator** control surfaces. This is
deliberately **blackbox**: Prometheus + `blackbox_exporter` probe the Portal's public issuer-key
route (`/v1/tokens/pubkey`) and the Coordinator's `/healthz`, then alert when they fail or slow. It
observes only *liveness of your own services* — **no user data, no per-connection data, no metrics
endpoint on the apps** (they expose none).

## Privacy posture (why blackbox, and what is NOT monitored)
- **Nodes (data plane) are NOT monitored here.** They have no application traffic-log store, but
  operational stdout can be retained by the host/container runtime. Probing them would add
  availability metadata about the tunnel path. Leave them out.
- **No whitebox `/metrics`.** Adding a metrics endpoint to the Portal/Coordinator would be a new
  data-collection surface that must first pass a PII review (PD-1). It is a deliberate follow-up,
  not shipped here. Blackbox `/healthz` probing collects nothing about users.
- The only intended signal is "is my own control surface up, and how fast" — operator operations,
  not user behavior. The monitoring service still retains probe timestamps/latency and its own logs;
  bound and audit that operational retention.

## Deploy
> This stack is an engineering/staging example, not an approved production deployment.

1. Edit `prometheus.yml`: replace the two placeholder HTTPS targets with the Portal
   `/v1/tokens/pubkey` and Coordinator `/healthz` URLs.
2. Edit `alertmanager.yml`: fill in a real receiver (the webhook URL is a placeholder).
3. `docker compose -f compose.monitoring.yaml up -d` (on an ops host, NOT a node).
4. Pin every image by `@sha256:` for staging evidence; an immutable digest alone is not production
   approval (the tags here are placeholders).

## Log handling

The reviewed public Portal/Coordinator Compose examples disable Caddy HTTP access logs and use the
`none` driver for all Caddy operational output. Their application/wallet services use a bounded
Docker `local` driver (`5m`, two files). Those files are operationally useful but are **not assumed
anonymous** and do not control host backups or provider telemetry.

This separate monitoring example still needs its own bounded log policy. Add to each monitoring
service in the operator-specific Compose overlay:

```yaml
    logging:
      driver: local
      options: { max-size: "5m", max-file: "2" }
```

`nil-node` has no application traffic-log file, but it emits operational stdout. The container/host
log driver can persist that output, so it also needs an explicit bounded/volatile policy.
