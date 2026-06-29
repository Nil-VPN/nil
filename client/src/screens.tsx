import { useEffect, useState } from "react";
import * as api from "./lib/commands";
import type { SubscriptionStatus } from "./lib/commands";
import type { AnonymousAccount, ConnState, PortalConfig } from "./lib/types";
import { HonestLimits, HonestyBanner, StatusPill, TokenBalanceBadge } from "./components";

/** First-run: choose how to create/recover an account. Anonymous is the default. */
export function FirstRunScreen({
  busy,
  onAnonymous,
  onEmail,
  onRecover,
}: {
  busy: boolean;
  onAnonymous: () => void;
  onEmail: () => void;
  onRecover: () => void;
}) {
  return (
    <div className="screen">
      <h1 className="brand">NIL VPN</h1>
      <p className="tagline">"What do we have on you? Nil."</p>

      <button className="btn btn-primary" disabled={busy} onClick={onAnonymous}>
        Create anonymous account (no email)
      </button>
      <p className="hint">
        Nothing personal is stored — no email, no name, no signup IP. You'll get a 7-word
        recovery phrase. Losing it means losing the account; there's no email to reset.
      </p>

      <button className="btn btn-secondary" disabled={busy} onClick={onEmail}>
        Use email (easier recovery)
      </button>

      <button className="link" disabled={busy} onClick={onRecover}>
        I already have an account → recover
      </button>

      <HonestyBanner />
    </div>
  );
}

/** Shows the 7-word phrase + recovery code exactly once, wallet-seed style. */
export function RecoveryPhraseScreen({
  account,
  onContinue,
}: {
  account: AnonymousAccount;
  onContinue: () => void;
}) {
  const [written, setWritten] = useState(false);
  return (
    <div className="screen">
      <h2>Write down your recovery phrase</h2>
      <p className="warn">
        These 7 words <strong>are</strong> your account. Write them down and store them
        offline. This is shown only once — we cannot recover it for you.
      </p>

      <ol className="phrase">
        {account.recovery_phrase.map((w, i) => (
          <li key={i}>
            <span className="word-num">{i + 1}</span>
            {w}
          </li>
        ))}
      </ol>

      <div className="field">
        <span className="field-label">One-time recovery code</span>
        <code className="code">{account.recovery_code}</code>
      </div>

      <div className="field">
        <span className="field-label">Account number</span>
        <code className="code small">{account.account_number}</code>
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={written}
          onChange={(e) => setWritten(e.target.checked)}
        />
        I've written down my recovery phrase and code.
      </label>

      <button className="btn btn-primary" disabled={!written} onClick={onContinue}>
        Continue
      </button>
    </div>
  );
}

/** Recover an existing account from the phrase + code. */
export function RecoverAccountScreen({
  busy,
  onSubmit,
  onBack,
}: {
  busy: boolean;
  onSubmit: (phrase: string[], code: string) => void;
  onBack: () => void;
}) {
  const [phrase, setPhrase] = useState("");
  const [code, setCode] = useState("");
  const words = phrase.trim().split(/\s+/).filter(Boolean);

  return (
    <div className="screen">
      <h2>Recover your account</h2>
      <label className="field">
        <span className="field-label">Your 7 words (separated by spaces)</span>
        <textarea
          className="input"
          rows={3}
          value={phrase}
          placeholder="word1 word2 word3 word4 word5 word6 word7"
          onChange={(e) => setPhrase(e.target.value)}
        />
      </label>
      <label className="field">
        <span className="field-label">Recovery code</span>
        <input
          className="input"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
      </label>

      <button
        className="btn btn-primary"
        disabled={busy || words.length !== 7 || code.trim().length === 0}
        onClick={() => onSubmit(words, code.trim())}
      >
        Recover
      </button>
      <button className="link" disabled={busy} onClick={onBack}>
        ← Back
      </button>
    </div>
  );
}

/** "Use email" path — Phase 0 surfaces the not-yet-available message from the Portal. */
export function EmailSignupScreen({
  busy,
  onSubmit,
  onBack,
}: {
  busy: boolean;
  onSubmit: (email: string) => void;
  onBack: () => void;
}) {
  const [email, setEmail] = useState("");
  return (
    <div className="screen">
      <h2>Use email</h2>
      <p className="hint">
        Email accounts store only an encrypted email. (Not available in this Phase&nbsp;0
        preview — anonymous accounts are fully working.)
      </p>
      <label className="field">
        <span className="field-label">Email address</span>
        <input
          className="input"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </label>
      <button
        className="btn btn-primary"
        disabled={busy || email.trim().length === 0}
        onClick={() => onSubmit(email.trim())}
      >
        Continue
      </button>
      <button className="link" disabled={busy} onClick={onBack}>
        ← Back
      </button>
    </div>
  );
}

/** Main screen: connect/disconnect + status + on-device token balance, driven by the engine. */
export function MainScreen({
  onError,
  onNavigate,
}: {
  onError: (msg: string) => void;
  onNavigate: (screen: "buy" | "subscribe" | "settings") => void;
}) {
  const [state, setState] = useState<ConnState>("disconnected");
  const [balance, setBalance] = useState<number | null>(null);
  const [cfg, setCfg] = useState<PortalConfig | null>(null);
  const [sub, setSub] = useState<SubscriptionStatus | null>(null);

  useEffect(() => {
    api.status().then(setState).catch((e) => onError(String(e)));
    api.tokenBalance().then(setBalance).catch(() => setBalance(null));
    api.getConfig().then(setCfg).catch(() => setCfg(null));
    api.subscriptionStatus().then((s) => setSub(s ?? null)).catch(() => setSub(null));
  }, [onError]);

  const busy = state === "connecting" || state === "disconnecting";
  const connected = state === "connected";
  // A real (attested) path is configured when a Coordinator URL is set.
  const realPath = !!cfg && cfg.coordinator_url.trim().length > 0;
  const subscribed = sub?.entitlement === "active";
  const activeUntil = sub?.until ? new Date(sub.until * 1000).toLocaleDateString() : null;
  // Fail-closed: with a Coordinator configured you need EITHER an active subscription (connect mints
  // a token on demand) or a leftover token to connect — otherwise no token, no tunnel.
  const needToken = realPath && !subscribed && (balance ?? 0) === 0;

  async function toggle() {
    try {
      if (state === "disconnected") {
        setState("connecting"); // optimistic
        setState(await api.connect());
      } else if (state === "connected") {
        setState("disconnecting"); // optimistic
        setState(await api.disconnect());
      }
    } catch (e) {
      onError(String(e));
      setState(await api.status().catch(() => "disconnected" as ConnState));
    } finally {
      api.tokenBalance().then(setBalance).catch(() => {});
    }
  }

  return (
    <div className="screen main">
      <div className="topbar">
        <TokenBalanceBadge count={balance} />
        <button className="icon-btn" title="Settings" onClick={() => onNavigate("settings")}>
          ⚙
        </button>
      </div>

      <h1 className="brand">NIL VPN</h1>
      <StatusPill state={state} />

      {realPath && (
        <p className="hint sub-status">
          {subscribed
            ? `Subscription active${activeUntil ? ` until ${activeUntil}` : ""} — connecting mints a token on demand.`
            : "No active subscription."}
        </p>
      )}

      <button
        className={`toggle ${connected ? "toggle-on" : "toggle-off"}`}
        // A token is required to CONNECT, but never to disconnect — otherwise, once the last token is
        // consumed by the active connection (balance → 0), the user could no longer turn the VPN off.
        disabled={busy || (needToken && !connected)}
        onClick={toggle}
      >
        {connected ? "Disconnect" : "Connect"}
      </button>

      <p className="hint">
        {connected
          ? realPath
            ? "Connected through an attested node — the client verified its hardware report before any packet flowed."
            : "Connected via the in-memory loopback transport (no Coordinator configured — no real tunnel)."
          : needToken
            ? "Subscribe — or buy a connection token — to connect (fail-closed: no token, no tunnel)."
            : realPath
              ? subscribed
                ? "Tap Connect — your subscription mints a token and brings up the attested tunnel."
                : "Tap Connect to redeem a token and bring up the attested tunnel."
              : "Tap Connect to exercise the engine through the loopback transport."}
      </p>

      <button className="btn btn-primary" disabled={busy} onClick={() => onNavigate("subscribe")}>
        {subscribed ? "Manage subscription" : "Subscribe"}
      </button>
      <button className="btn btn-secondary" disabled={busy} onClick={() => onNavigate("buy")}>
        Buy a one-off connection token
      </button>

      <HonestLimits />
    </div>
  );
}

/** Buy connection tokens: pay (Monero / comp id), then claim a blind-signed, unlinkable token. */
export function BuyTokensScreen({
  busy,
  onBuy,
  onBack,
}: {
  busy: boolean;
  onBuy: (paymentId: string) => void;
  onBack: () => void;
}) {
  const [paymentId, setPaymentId] = useState("");
  const [cfg, setCfg] = useState<PortalConfig | null>(null);
  useEffect(() => {
    api.getConfig().then(setCfg).catch(() => setCfg(null));
  }, []);

  const address = cfg?.monero_address?.trim() ?? "";
  return (
    <div className="screen">
      <h2>Buy connection tokens</h2>
      <p className="hint">
        Pay, then claim a token. The token is blind-signed, so what you pay is mathematically
        unlinkable to what you do (Pillar 4). One token = one connection; top up anytime.
      </p>

      {address ? (
        <div className="field">
          <span className="field-label">Monero deposit address</span>
          <code className="code">{address}</code>
          <span className="hint">Send payment, then enter the payment id you received below.</span>
        </div>
      ) : (
        <p className="hint">
          No Monero address is configured. For the closed alpha, enter a comp / invite payment id
          from the operator. (Set a deposit address in Settings for self-serve Monero.)
        </p>
      )}

      <label className="field">
        <span className="field-label">Payment id</span>
        <input
          className="input"
          value={paymentId}
          placeholder="payment-or-comp-id"
          onChange={(e) => setPaymentId(e.target.value)}
        />
      </label>

      <button
        className="btn btn-primary"
        disabled={busy || paymentId.trim().length === 0}
        onClick={() => onBuy(paymentId.trim())}
      >
        Claim token
      </button>
      <button className="link" disabled={busy} onClick={onBack}>
        ← Back
      </button>
    </div>
  );
}

/** Subscribe / renew (ADR-0007): pay once, then connect freely while active. The app mints unlinkable
 *  tokens on demand, so logging back in on any device reconnects with no extra payment. */
export function SubscribeScreen({
  onError,
  onBack,
}: {
  onError: (msg: string) => void;
  onBack: () => void;
}) {
  // undefined = still loading; null = no account / unknown.
  const [status, setStatus] = useState<SubscriptionStatus | null | undefined>(undefined);
  const [reference, setReference] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState<PortalConfig | null>(null);

  useEffect(() => {
    api.subscriptionStatus().then((s) => setStatus(s ?? null)).catch(() => setStatus(null));
    api.getConfig().then(setCfg).catch(() => setCfg(null));
  }, []);

  const active = status?.entitlement === "active";
  const until = status?.until ? new Date(status.until * 1000).toLocaleString() : null;
  const address = cfg?.monero_address?.trim() ?? "";

  async function start() {
    setBusy(true);
    try {
      setReference(await api.subscribe());
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function claim() {
    if (!reference) return;
    setBusy(true);
    try {
      const next = await api.activateSubscription(reference);
      setStatus(next);
      setReference(null); // activated — clear the pending reference
    } catch (e) {
      // The Rust side returns "payment not confirmed yet — wait …, then try again" until it lands;
      // surface it verbatim so the user knows to retry, not that something broke.
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="screen">
      <h2>Subscription</h2>
      <p className="hint">
        {active
          ? `Active until ${until}. While active, connecting mints unlinkable tokens on demand — log back in on any device and reconnect, no extra payment (Pillar 4).`
          : "Pay once for a month of access. While active, the app mints unlinkable connection tokens on demand, so what you pay stays unlinkable to what you do — and re-login on any device reconnects without paying again."}
      </p>

      {!reference ? (
        <button
          className="btn btn-primary"
          disabled={busy || status === undefined}
          onClick={start}
        >
          {active ? "Renew — extend +30 days" : "Start subscription"}
        </button>
      ) : (
        <>
          <div className="field">
            <span className="field-label">Pay this reference (as your Monero payment id)</span>
            <code className="code">{reference}</code>
            {address ? (
              <>
                <span className="field-label">to the deposit address</span>
                <code className="code">{address}</code>
              </>
            ) : (
              <span className="hint">
                No Monero address is configured — for the closed alpha, give this reference to the
                operator as your comp / invite id. (Set a deposit address in Settings for self-serve.)
              </span>
            )}
            <span className="hint">Send the payment, then tap below — it can take a few minutes to confirm.</span>
          </div>
          <button className="btn btn-primary" disabled={busy} onClick={claim}>
            I've paid — activate
          </button>
        </>
      )}

      <button className="link" disabled={busy} onClick={onBack}>
        ← Back
      </button>
    </div>
  );
}

/** Settings: operator endpoints + toggles. "Restore live defaults" points at api/ctrl.nilvpn.com. */
export function SettingsScreen({
  onError,
  onBack,
}: {
  onError: (msg: string) => void;
  onBack: () => void;
}) {
  const [cfg, setCfg] = useState<PortalConfig | null>(null);
  const [saved, setSaved] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  useEffect(() => {
    api.getConfig().then(setCfg).catch((e) => onError(String(e)));
    api
      .platform()
      .then((p) => setIsMobile(p === "android" || p === "ios"))
      .catch(() => setIsMobile(false));
  }, [onError]);

  if (!cfg) {
    return (
      <div className="screen">
        <h2>Settings</h2>
        <p className="hint">Loading…</p>
      </div>
    );
  }

  const set = (patch: Partial<PortalConfig>) => {
    setCfg({ ...cfg, ...patch });
    setSaved(false);
  };

  async function save() {
    try {
      await api.setConfig(cfg!);
      setSaved(true);
    } catch (e) {
      onError(String(e));
    }
  }

  return (
    <div className="screen">
      <h2>Settings</h2>
      <label className="field">
        <span className="field-label">Portal URL (accounts + tokens)</span>
        <input className="input" value={cfg.portal_url} onChange={(e) => set({ portal_url: e.target.value })} />
      </label>
      <label className="field">
        <span className="field-label">Coordinator URL (attested path)</span>
        <input className="input" value={cfg.coordinator_url} onChange={(e) => set({ coordinator_url: e.target.value })} />
        <span className="hint">Empty = loopback dev mode (no real tunnel).</span>
      </label>
      <label className="field">
        <span className="field-label">Monero deposit address (optional)</span>
        <input className="input" value={cfg.monero_address} onChange={(e) => set({ monero_address: e.target.value })} />
      </label>
      <label className="checkbox">
        <input
          type="checkbox"
          checked={cfg.kill_switch}
          onChange={(e) => set({ kill_switch: e.target.checked })}
        />
        Kill-switch — block all traffic if the tunnel drops (recommended).
      </label>

      {isMobile && (
        <div className="field">
          <span className="field-label">Always-on VPN (persistent kill-switch)</span>
          <span className="hint">
            While connected, all traffic is already forced through the tunnel. To also block traffic
            if NIL stops or the phone reboots, turn on Android&apos;s <strong>Always-on VPN</strong>{" "}
            and <strong>Block connections without VPN</strong>. This is an OS setting — the app can
            take you there, but cannot enable it for you.
          </span>
          <button className="btn" onClick={() => api.openAlwaysOnSettings().catch((e) => onError(String(e)))}>
            Open VPN settings
          </button>
        </div>
      )}

      <details>
        <summary>Advanced</summary>
        <label className="field">
          <span className="field-label">Direct node host (bypass Coordinator)</span>
          <input className="input" value={cfg.node_host} onChange={(e) => set({ node_host: e.target.value })} />
        </label>
        <label className="field">
          <span className="field-label">Pinned measurement (hex; blank on the Coordinator path)</span>
          <input className="input" value={cfg.expected_measurement} onChange={(e) => set({ expected_measurement: e.target.value })} />
        </label>
        <label className="field">
          <span className="field-label">TEE</span>
          <select className="input" value={cfg.expected_tee} onChange={(e) => set({ expected_tee: e.target.value })}>
            <option value="sev-snp">AMD SEV-SNP</option>
            <option value="tdx">Intel TDX</option>
          </select>
        </label>
      </details>

      <button className="btn btn-primary" onClick={save}>
        {saved ? "Saved ✓" : "Save"}
      </button>
      <button
        className="link"
        onClick={() => set({ portal_url: "https://api.nilvpn.com", coordinator_url: "https://ctrl.nilvpn.com" })}
      >
        Restore live defaults (nilvpn.com)
      </button>
      <button className="link" onClick={onBack}>
        ← Back
      </button>

      <HonestLimits />
    </div>
  );
}
