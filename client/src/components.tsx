import type { ConnState } from "./lib/types";

/** Persistent honesty note — implemented policy and live validation are deliberately distinct. */
export function HonestyBanner() {
  return (
    <p className="honesty">
      A working VPN can hide traffic from your local network and ISP — it is <strong>not</strong>{" "}
      anonymity. Release desktop code requires a multi-hop, attested MASQUE path and embedded
      trust roots. NIL is still an engineering alpha: live TEE and independent-operator deployment
      are unvalidated, and the packaged native Connect path refuses to start until it supports
      multi-hop.
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

/** Local on-device count of prefetched, blind-signed connection passes. */
export function TokenBalanceBadge({ count }: { count: number | null }) {
  const label = count === null ? "…" : `${count} pass${count === 1 ? "" : "es"}`;
  return (
    <span className={`badge ${count === 0 ? "badge-empty" : ""}`} title="Locally prefetched private connection passes">
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
        <li><strong>Encrypted path:</strong> after a tunnel is established, traffic is designed to leave through MASQUE instead of your ISP/local network.</li>
        <li><strong>Blind-signed passes:</strong> no direct cryptographic join links mint to redemption, but timing, IP, payment records, or a small user set can still correlate events.</li>
        <li><strong>Attestation gate:</strong> the code checks a fresh report against embedded roots before accepting a hop; NIL has not yet validated its full chain on a live TEE fleet.</li>
        <li><strong>Not anonymity.</strong> A VPN is not Tor; the exit node still sees your destinations.</li>
        <li><strong>Trust split is policy, not deployment proof:</strong> release desktop paths require at least two hops, but independent operators have not been demonstrated live.</li>
        <li><strong>Native release limitation:</strong> Android, iOS, and the macOS extension refuse to connect until their datapaths support multi-hop.</li>
        <li><strong>Physical attacks remain:</strong> TEE.Fail-class memory attacks can undermine a hardware report.</li>
        <li><strong>Release chain incomplete:</strong> source, image, guest measurement, and the exact running node are not yet one independently verified artifact chain.</li>
        <li><strong>Lose your 12-word phrase → lose the account.</strong> There's no email reset by design.</li>
      </ul>
    </div>
  );
}
