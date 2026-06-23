import { useCallback, useState } from "react";
import "./App.css";
import * as api from "./lib/commands";
import type { AnonymousAccount } from "./lib/types";
import { ErrorBanner } from "./components";
import {
  BuyTokensScreen,
  EmailSignupScreen,
  FirstRunScreen,
  MainScreen,
  RecoverAccountScreen,
  RecoveryPhraseScreen,
  SettingsScreen,
} from "./screens";

type Screen = "firstrun" | "email" | "phrase" | "recover" | "main" | "buy" | "settings";

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

  async function handleEmail(email: string) {
    setBusy(true);
    setError(null);
    try {
      await api.createEmailAccount(email);
      setScreen("main");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleRecover(phrase: string[], code: string) {
    setBusy(true);
    setError(null);
    try {
      await api.recoverAccount(phrase, code);
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
          onEmail={() => setScreen("email")}
          onRecover={() => setScreen("recover")}
        />
      )}
      {screen === "email" && (
        <EmailSignupScreen busy={busy} onSubmit={handleEmail} onBack={() => setScreen("firstrun")} />
      )}
      {screen === "phrase" && account && (
        <RecoveryPhraseScreen account={account} onContinue={() => setScreen("main")} />
      )}
      {screen === "recover" && (
        <RecoverAccountScreen busy={busy} onSubmit={handleRecover} onBack={() => setScreen("firstrun")} />
      )}
      {screen === "main" && <MainScreen onError={showError} onNavigate={setScreen} />}
      {screen === "buy" && (
        <BuyTokensScreen busy={busy} onBuy={handleBuy} onBack={() => setScreen("main")} />
      )}
      {screen === "settings" && (
        <SettingsScreen onError={showError} onBack={() => setScreen("main")} />
      )}
    </main>
  );
}

export default App;
