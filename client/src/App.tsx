import { useCallback, useState } from "react";
import "./App.css";
import * as api from "./lib/commands";
import type { AnonymousAccount } from "./lib/types";
import { ErrorBanner } from "./components";
import {
  BuyTokensScreen,
  FirstRunScreen,
  MainScreen,
  RecoverAccountScreen,
  RecoveryPhraseScreen,
  SettingsScreen,
  SubscribeScreen,
} from "./screens";

type Screen =
  | "firstrun"
  | "phrase"
  | "recover"
  | "main"
  | "buy"
  | "subscribe"
  | "settings";

function App() {
  const [screen, setScreen] = useState<Screen>("firstrun");
  const [account, setAccount] = useState<AnonymousAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const showError = useCallback((msg: string) => setError(msg), []);

  async function handleAnonymous() {
    setBusy(true);
    setError(null);
    try {
      const acct = await api.createAnonymousAccount();
      setAccount(acct);
      setScreen("phrase");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirmAccount() {
    if (!account) return;
    setBusy(true);
    setError(null);
    try {
      await api.confirmAnonymousAccount(account.recovery_phrase, account.account_number);
      setAccount(null);
      setScreen("main");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleRecover(phrase: string[]) {
    setBusy(true);
    setError(null);
    try {
      await api.recoverAccount(phrase);
      setScreen("main");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleBuy(paymentId: string) {
    setBusy(true);
    setError(null);
    try {
      await api.buyTokens(paymentId);
      setScreen("main"); // balance refreshes on the main screen
    } catch (e) {
      // The Rust side returns honest, user-facing messages (e.g. payment not confirmed,
      // already issued) — surface them verbatim.
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="app">
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      {screen === "firstrun" && (
        <FirstRunScreen
          busy={busy}
          onAnonymous={handleAnonymous}
          onRecover={() => setScreen("recover")}
        />
      )}
      {screen === "phrase" && account && (
        // Drop the recovery phrase / account number from app state once the user leaves the
        // display screen — the frontend has no further need for them, so they must not linger in the
        // JS heap (DevTools / heap dump / XSS reach) for the rest of the session (SOUL §3, PD-2).
        <RecoveryPhraseScreen
          account={account}
          busy={busy}
          onContinue={handleConfirmAccount}
        />
      )}
      {screen === "recover" && (
        <RecoverAccountScreen busy={busy} onSubmit={handleRecover} onBack={() => setScreen("firstrun")} />
      )}
      {screen === "main" && <MainScreen onError={showError} onNavigate={setScreen} />}
      {screen === "buy" && (
        <BuyTokensScreen busy={busy} onBuy={handleBuy} onBack={() => setScreen("main")} />
      )}
      {screen === "subscribe" && (
        <SubscribeScreen onError={showError} onBack={() => setScreen("main")} />
      )}
      {screen === "settings" && (
        <SettingsScreen onError={showError} onBack={() => setScreen("main")} />
      )}
    </main>
  );
}

export default App;
