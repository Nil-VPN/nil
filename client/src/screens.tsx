import { useEffect, useState } from "react";
import * as api from "./lib/commands";
import type { SubscriptionStatus } from "./lib/commands";
import type { AnonymousAccount, ConnState, PortalConfig } from "./lib/types";
import { HonestLimits, HonestyBanner, StatusPill, TokenBalanceBadge } from "./components";

// The Rust background refiller owns all network activity and its randomized schedule. This fixed,
// local-only poll merely notices when a prefetched pass has reached the on-device store.
const TOKEN_BALANCE_POLL_MS = 5_000;

/** First-run: choose how to create/recover an account. Anonymous is the default. */
export function FirstRunScreen({
  busy,
  onAnonymous,
  onRecover,
}: {
  busy: boolean;
  onAnonymous: () => void;
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
        Nothing personal is stored — no email, no name, no signup IP. Your device creates a
        checksummed 12-word recovery phrase; it is never sent to NIL. Losing it means losing the
        account because there is no email reset.
      </p>

      <button className="link" disabled={busy} onClick={onRecover}>
        I already have an account → recover
      </button>

      <HonestyBanner />
    </div>
  );
}

/** Shows the client-generated 12-word BIP39 phrase exactly once, wallet-seed style. */
export function RecoveryPhraseScreen({
  account,
  busy,
  onContinue,
}: {
  account: AnonymousAccount;
  busy: boolean;
  onContinue: () => void;
}) {
  const [written, setWritten] = useState(false);
  return (
    <div className="screen">
      <h2>Write down your recovery phrase</h2>
      <p className="warn">
        These 12 checksummed words <strong>are</strong> your account. They were generated on this
        device and were never sent to NIL. Store them offline; we cannot recover them for you.
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
        <span className="field-label">Account number</span>
        <code className="code small">{account.account_number}</code>
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={written}
          onChange={(e) => setWritten(e.target.checked)}
        />
        I've written down and checked all 12 words.
      </label>

      <button className="btn btn-primary" disabled={!written || busy} onClick={onContinue}>
        Continue
      </button>
    </div>
  );
}

/** Recover an existing account by deriving its auth key locally from the checksummed mnemonic. */
export function RecoverAccountScreen({
  busy,
  onSubmit,
  onBack,
}: {
  busy: boolean;
  onSubmit: (phrase: string[]) => void;
  onBack: () => void;
}) {
  const [phrase, setPhrase] = useState("");
  const words = phrase.trim().split(/\s+/).filter(Boolean);

  return (
    <div className="screen">
      <h2>Recover your account</h2>
      <label className="field">
        <span className="field-label">Your 12 words (separated by spaces)</span>
        <textarea
          className="input"
          rows={3}
          value={phrase}
          placeholder="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
          onChange={(e) => setPhrase(e.target.value)}
        />
      </label>
      <button
        className="btn btn-primary"
        disabled={busy || words.length !== 12}
        onClick={() => onSubmit(words)}
      >
        Recover
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
    let active = true;
    const refreshBalance = () => {
      api
        .tokenBalance()
        .then((next) => {
          if (active) setBalance(next);
        })
        .catch(() => {
          // Unknown balance is treated like zero below, so a storage/backend error fails closed.
          if (active) setBalance(null);
        });
    };

    api.status().then(setState).catch((e) => onError(String(e)));
    refreshBalance();
    api.getConfig().then(setCfg).catch(() => setCfg(null));
    api.subscriptionStatus().then((s) => setSub(s ?? null)).catch(() => setSub(null));
    const balancePoll = window.setInterval(refreshBalance, TOKEN_BALANCE_POLL_MS);
    return () => {
      active = false;
      window.clearInterval(balancePoll);
    };
  }, [onError]);

  const busy = state === "connecting" || state === "disconnecting";
  const connected = state === "connected";
  const disconnectable = connected || state === "disconnecting";
  // Only the Coordinator path consumes a subscription pass. The direct-node override is a
  // debug-only integration path and is labelled separately below.
  const realPath = !!cfg && cfg.coordinator_url.trim().length > 0;
  const directDebugPath = !!cfg && !realPath && cfg.node_host.trim().length > 0;
  const subscribed = sub?.entitlement === "active";
  const activeUntil = sub?.until ? new Date(sub.until * 1000).toLocaleDateString() : null;
  // Subscription status authorizes the separate background refiller. A real connection still
  // requires a pass already present in the local store.
  const needPreparedPass = realPath && (balance ?? 0) < 1;
  const checkingPreparedPass = realPath && balance === null;
  const preparingSubscribedPasses = needPreparedPass && subscribed && balance === 0;

  let connectionHint: string;
  if (connected) {
    if (realPath) {
      connectionHint =
        "Connected through an attested path — the client verified every hop's hardware report before accepting the tunnel.";
    } else if (directDebugPath) {
      connectionHint =
        "Connected through the debug-only direct-node path. It bypasses Coordinator redemption and is unavailable in release builds.";
    } else {
      connectionHint =
        "Connected through the debug-only in-memory loopback seam — this is not a VPN tunnel and cannot occur in a release build.";
    }
  } else if (cfg === null) {
    connectionHint = "Loading connection settings…";
  } else if (checkingPreparedPass) {
    connectionHint = "Checking for a locally prepared private connection pass…";
  } else if (preparingSubscribedPasses) {
    connectionHint =
      "Private connection passes are being prepared in the background. Connect will unlock when a prefetched pass is stored on this device.";
  } else if (needPreparedPass) {
    connectionHint =
      "Subscribe to prepare private connection passes in the background, or buy a one-off pass (fail-closed: no stored pass, no tunnel).";
  } else if (realPath) {
    connectionHint =
      "Tap Connect to use one locally prepared private connection pass and bring up the attested tunnel.";
  } else if (directDebugPath) {
    connectionHint =
      "Debug-only direct-node mode bypasses Coordinator redemption and does not consume a connection pass. Release builds refuse this path.";
  } else {
    connectionHint =
      "No Coordinator is configured. Debug builds can exercise the in-memory loopback seam (not a VPN); release builds refuse to connect.";
  }

  async function toggle() {
    try {
      if (state === "disconnected") {
        setState("connecting"); // optimistic
        setState(await api.connect());
      } else if (disconnectable) {
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
            ? `Subscription active${activeUntil ? ` until ${activeUntil}` : ""}. Private connection passes are prepared in small blind-signed batches at randomized times in the background.`
            : "No active subscription. Connect requires one private connection pass already stored on this device."}
        </p>
      )}

      <button
        className={`toggle ${disconnectable ? "toggle-on" : "toggle-off"}`}
        // A prepared pass is required to CONNECT, but never to disconnect — otherwise, once the last
        // pass is consumed by the active connection (balance → 0), the user could not turn the VPN off.
        // Keep Connect locked until config loads too, so the initial unknown state cannot bypass the gate.
        disabled={
          state === "connecting" || (!disconnectable && (cfg === null || needPreparedPass))
        }
        onClick={toggle}
      >
        {state === "disconnecting" ? "Retry cleanup" : connected ? "Disconnect" : "Connect"}
      </button>

      <p className="hint">{connectionHint}</p>

      <button className="btn btn-primary" disabled={busy} onClick={() => onNavigate("subscribe")}>
        {subscribed ? "Manage subscription" : "Subscribe"}
      </button>
      <button className="btn btn-secondary" disabled={busy} onClick={() => onNavigate("buy")}>
        Buy a one-off connection pass
      </button>

      <HonestLimits />
    </div>
  );
}

/** Buy one connection pass: payment is visible to Portal, while the later token is blind-signed. */
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
      <h2>Buy a one-off connection pass</h2>
      <p className="hint">
        Pay, then claim a blind-signed pass. The Portal sees the payment, but cannot derive the
        unblinded pass later redeemed at the Coordinator. Network timing can still correlate
        events, so this is not anonymity. Each Connect attempt consumes one locally stored pass,
        and a later network/tunnel failure may still consume it. Top up anytime.
      </p>

      {address ? (
        <div className="field">
          <span className="field-label">Monero deposit address</span>
          <code className="code">{address}</code>
          <span className="hint">Send payment, then enter the payment id you received below.</span>
        </div>
      ) : (
        <p className="hint">
          No Monero deposit address is configured. This screen can claim only a confirmed,
          Portal-minted payment reference supplied through the operator or a debug harness.
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
        Claim pass
      </button>
      <button className="link" disabled={busy} onClick={onBack}>
        ← Back
      </button>
    </div>
  );
}

/** Subscribe / renew (ADR-0007): subscription checks and batched pass preparation happen in the
 *  background, away from the moment Connect consumes a locally stored pass. */
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
          ? `Active until ${until}. NIL prepares blind-signed connection passes in small batches at randomized times in the background. Connect uses only a pass already stored on this device; after signing in on a new device, allow time for its first batch.`
          : "Pay once for a month of access. While active, NIL prepares blind-signed connection passes in small batches at randomized times in the background. Connect waits for a locally stored pass, helping reduce timing correlation between account activity and a connection."}
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

/** Settings: operator endpoints + toggles. "Restore live defaults" points at api/ctrl.nilvpn.net. */
export function SettingsScreen({
  onError,
  onBack,
}: {
  onError: (msg: string) => void;
  onBack: () => void;
}) {
  const [cfg, setCfg] = useState<PortalConfig | null>(null);
  const [saved, setSaved] = useState(false);
  const [platform, setPlatform] = useState<string>("other");
  useEffect(() => {
    api.getConfig().then(setCfg).catch((e) => onError(String(e)));
    api
      .platform()
      .then(setPlatform)
      .catch(() => setPlatform("other"));
  }, [onError]);
  const isMobile = platform === "android" || platform === "ios";

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
        <span className="field-label">Portal URL (accounts + connection passes)</span>
        <input className="input" value={cfg.portal_url} onChange={(e) => set({ portal_url: e.target.value })} />
        <span className="hint">
          Release builds require HTTPS. Debug builds additionally allow HTTP on genuine loopback
          addresses for local integration.
        </span>
      </label>
      <label className="field">
        <span className="field-label">Coordinator URL (attested path)</span>
        <input className="input" value={cfg.coordinator_url} onChange={(e) => set({ coordinator_url: e.target.value })} />
        <span className="hint">
          Release builds require an HTTPS Coordinator. Empty enables the non-VPN loopback seam in
          debug builds only; release builds refuse to connect.
        </span>
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
          {platform === "ios" ? (
            <>
              <span className="hint">
                While connected, NIL already forces all traffic through the tunnel. iOS has no
                user-facing system-wide Always-on VPN switch (it&apos;s for managed devices), so it
                can&apos;t guarantee blocking traffic if NIL stops. Open Settings to review the NIL VPN
                configuration.
              </span>
              <button className="btn" onClick={() => api.openAlwaysOnSettings().catch((e) => onError(String(e)))}>
                Open Settings
              </button>
            </>
          ) : (
            <>
              <span className="hint">
                While connected, all traffic is already forced through the tunnel. To also block traffic
                if NIL stops or the phone reboots, turn on Android&apos;s <strong>Always-on VPN</strong>{" "}
                and <strong>Block connections without VPN</strong>. This is an OS setting — the app can
                take you there, but cannot enable it for you.
              </span>
              <button className="btn" onClick={() => api.openAlwaysOnSettings().catch((e) => onError(String(e)))}>
                Open VPN settings
              </button>
            </>
          )}
        </div>
      )}

      <details>
        <summary>Advanced</summary>
        <label className="field">
          <span className="field-label">Debug-only direct node host (bypasses Coordinator)</span>
          <input className="input" value={cfg.node_host} onChange={(e) => set({ node_host: e.target.value })} />
          <span className="hint">
            Local integration only. It does not consume a connection pass and is unavailable in
            release builds.
          </span>
        </label>
        <label className="field">
          <span className="field-label">Optional embedded measurement selection (hex)</span>
          <input className="input" value={cfg.expected_measurement} onChange={(e) => set({ expected_measurement: e.target.value })} />
          <span className="hint">
            A release setting can only select a measurement already embedded in the signed client;
            it cannot add a new trust root. Debug direct-node tests use this as their explicit pin.
          </span>
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
        onClick={() => set({ portal_url: "https://api.nilvpn.net", coordinator_url: "https://ctrl.nilvpn.net" })}
      >
        Restore live defaults (nilvpn.net)
      </button>
      <button className="link" onClick={onBack}>
        ← Back
      </button>

      <HonestLimits />
    </div>
  );
}
