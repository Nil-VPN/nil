import { useEffect, useState } from "react";
import * as api from "./lib/commands";
import type { AnonymousAccount, ConnState } from "./lib/types";
import { HonestyBanner, StatusPill } from "./components";

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

/** Main screen: connect/disconnect toggle + status, driven by the loopback engine. */
export function MainScreen({ onError }: { onError: (msg: string) => void }) {
  const [state, setState] = useState<ConnState>("disconnected");

  useEffect(() => {
    api.status().then(setState).catch((e) => onError(String(e)));
  }, [onError]);

  const busy = state === "connecting" || state === "disconnecting";

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
    }
  }

  const connected = state === "connected";
  return (
    <div className="screen main">
      <h1 className="brand">NIL VPN</h1>
      <StatusPill state={state} />

      <button
        className={`toggle ${connected ? "toggle-on" : "toggle-off"}`}
        disabled={busy}
        onClick={toggle}
      >
        {connected ? "Disconnect" : "Connect"}
      </button>

      <p className="hint">
        {connected
          ? "Connected via NIL (Phase 0 demo: loopback transport — no real tunnel yet)."
          : "Tap Connect to exercise the engine through the loopback transport."}
      </p>
    </div>
  );
}
