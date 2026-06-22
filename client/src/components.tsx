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
