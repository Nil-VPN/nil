import type { ConnState } from "./lib/types";

/** Persistent honesty note — a VPN is not anonymity, and Phase 0 has no real tunnel. */
export function HonestyBanner() {
  return (
    <p className="honesty">
      A VPN hides your traffic from your local network and ISP — it is <strong>not</strong>{" "}
      anonymity. This Phase&nbsp;0 preview uses an in-memory loopback transport, so no real
      tunnel is established yet.
    </p>
  );
}

export function ErrorBanner({
  message,
  onDismiss,
}: {
  message: string | null;
  onDismiss: () => void;
}) {
  if (!message) return null;
  return (
    <div className="error-banner" role="alert">
      <span>{message}</span>
      <button className="error-dismiss" onClick={onDismiss} aria-label="Dismiss">
        ×
      </button>
    </div>
  );
}

const STATE_LABEL: Record<ConnState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting…",
  connected: "Connected",
  disconnecting: "Disconnecting…",
};

export function StatusPill({ state }: { state: ConnState }) {
  return <span className={`pill pill-${state}`}>{STATE_LABEL[state]}</span>;
}

/** Local on-device token count. Tokens are unlinkable to the account/payment. */
export function TokenBalanceBadge({ count }: { count: number | null }) {
  const label = count === null ? "…" : `${count} token${count === 1 ? "" : "s"}`;
  return (
    <span className={`badge ${count === 0 ? "badge-empty" : ""}`} title="On-device connection tokens (unlinkable to payment)">
      {label}
    </span>
  );
}

/** Honest limits — what NIL does and does not protect. Never overstate (SOUL / PD-8). */
export function HonestLimits() {
  return (
    <div className="limits">
      <h3>What this does — and doesn't</h3>
      <ul>
        <li><strong>Hides</strong> your traffic and destinations from your ISP/local network.</li>
        <li><strong>Unlinkable payment:</strong> tokens are blind-signed, so what you paid can't be tied to what you do.</li>
        <li><strong>Verifiable nodes:</strong> the client checks the node's hardware attestation before any packet flows — no proof, no traffic.</li>
        <li><strong>Not anonymity.</strong> A VPN is not Tor; the exit node still sees your destinations.</li>
        <li><strong>Single-hop (alpha):</strong> the one node sees your IP and your destination — not yet trust-split across operators.</li>
        <li><strong>Attestation caveat (TEE.Fail, Oct 2025):</strong> an attacker with physical memory access to a node could forge a report. Vendor/jurisdiction diversity across hops is the mitigation; the alpha is single-hop, so this is a real limit.</li>
        <li><strong>Lose your 7-word phrase → lose the account.</strong> There's no email reset by design.</li>
      </ul>
    </div>
  );
}
