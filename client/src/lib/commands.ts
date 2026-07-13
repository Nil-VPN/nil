// The single place the frontend calls into the Rust core. Tauri converts Rust
// snake_case command params to camelCase on the JS side, so we pass camelCase keys.
// A command that returns `Err(String)` on the Rust side rejects the promise with that
// string — callers catch it and show an error banner.

import { invoke } from "@tauri-apps/api/core";
import type {
  AnonymousAccount,
  ConnState,
  Location,
  PortalConfig,
  RecoverResult,
} from "./types";

export const createAnonymousAccount = () =>
  invoke<AnonymousAccount>("create_anonymous_account");

export const confirmAnonymousAccount = (phrase: string[], accountNumber: string) =>
  invoke<void>("confirm_anonymous_account", { phrase, accountNumber });

export const recoverAccount = (phrase: string[]) =>
  invoke<RecoverResult>("recover_account", { phrase });

// Host platform — lets us route Connect to the native datapath on mobile (the OS VpnService /
// PacketTunnel) instead of the in-process loopback engine. Cached after the first call.
let platformCache: Promise<string> | null = null;
export const platform = () => {
  if (!platformCache) {
    platformCache = invoke<string>("platform").catch((error) => {
      platformCache = null;
      throw error;
    });
  }
  return platformCache;
};
const isMobile = async () => {
  // Unknown platform is a hard error. Falling back to the desktop command on a mobile host would
  // bypass the native VPN lifecycle boundary (and a rejected promise must remain retryable).
  const p = await platform();
  return p === "android" || p === "ios";
};

/** Opaque local lifecycle binding; it contains no token, grant, node, account, or payment data. */
interface NativeConnectAttempt {
  reservationId: string;
}

// Desktop: the in-process engine brings up the real attested MASQUE tunnel. Debug builds retain a
// labelled loopback seam when no Coordinator is set; release builds compile that path out and fail
// explicitly. Mobile redeems the pass in the app process, then hands the attested endpoint + grant
// to the native OS VpnService/PacketTunnel. Either way Connect returns the verified engine state.
/** How long to wait for the native tunnel to confirm `up` before giving up (ms). */
const MOBILE_CONNECT_TIMEOUT_MS = 20000;

export const connect = async (): Promise<ConnState> => {
  if (await isMobile()) {
    // Rust privately performs consent preflight → ID-bound reserve/redeem → native start. Neither
    // the bearer token nor the resulting grant/node start args ever enter JavaScript.
    const { reservationId } = await invoke<NativeConnectAttempt>("extension_connect");
    // Poll through Rust. It commits the encrypted pending pass only after native status is `up` and
    // echoes this exact random ID, so stale service state cannot clear a newer reservation.
    const deadline = Date.now() + MOBILE_CONNECT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 500));
      const state = await invoke<ConnState>("extension_connection_status", { reservationId });
      if (state === "connected") return state;
      if (state === "disconnected") {
        await invoke<ConnState>("extension_disconnect").catch(() => {});
        throw new Error("Tunnel did not come up — attestation or connection failed.");
      }
    }
    await invoke<ConnState>("extension_disconnect").catch(() => {});
    throw new Error("Tunnel connect timed out.");
  }
  return invoke<ConnState>("connect");
};

export const disconnect = async (): Promise<ConnState> => {
  if (await isMobile()) {
    return invoke<ConnState>("extension_disconnect");
  }
  return invoke<ConnState>("disconnect");
};

/**
 * Deep-link to the OS VPN settings so the user can enable "Always-on VPN" + "Block connections
 * without VPN" — the PERSISTENT kill-switch that holds even if the NIL process dies. The app cannot
 * enable it programmatically (an honest limit), so it can only take the user there. Mobile only.
 */
export const openAlwaysOnSettings = async (): Promise<void> => {
  if (await isMobile()) {
    await invoke<void>("extension_open_vpn_settings");
  }
};

export const status = async (): Promise<ConnState> => {
  if (await isMobile()) {
    return invoke<ConnState>("extension_status");
  }
  return invoke<ConnState>("status");
};

export const listLocations = () => invoke<Location[]>("list_locations");
export const setTransportMode = (mode: string) =>
  invoke<void>("set_transport_mode", { mode });
export const setSplitTunnel = (enabled: boolean, apps: string[]) =>
  invoke<void>("set_split_tunnel", { enabled, apps });
export const toggleKillSwitch = (enabled: boolean) =>
  invoke<void>("toggle_kill_switch", { enabled });

// Tokens: buy (blind→issue→finalize against the Portal) and the local on-device count.
export const buyTokens = (paymentId: string) =>
  invoke<number>("buy_tokens", { paymentId });
export const tokenBalance = () => invoke<number>("token_balance");

// Subscription (ADR-0007): subscribe → pay the returned reference → activate. While active, the
// Rust background refiller prepares blind-signed passes in randomized batches. Connect only
// consumes a pass already in the local store; issuance is never coupled to the Connect action.
export interface SubscriptionStatus {
  entitlement: "none" | "active" | "expired";
  until?: number; // unix seconds; present iff entitlement === "active"
}

/** Begin/renew a subscription; returns the payment reference to pay (e.g. the Monero payment id). */
export const subscribe = () => invoke<string>("subscribe");

/** Claim a confirmed payment to activate/extend. Rejects with a "payment not confirmed yet" message
 *  until the payment lands — callers poll at a wide interval. */
export const activateSubscription = (paymentReference: string) =>
  invoke<SubscriptionStatus>("activate_subscription", { paymentReference });

/** The authenticated subscription status, or null if no account is cached on this device. */
export const subscriptionStatus = () =>
  invoke<SubscriptionStatus | null>("subscription_status");

/** Forget the cached account on this device (log out). Does not delete the account at the Portal. */
export const logout = () => invoke<void>("logout");

// Settings: operator endpoints + toggles, persisted and applied to the datapath.
export const getConfig = () => invoke<PortalConfig>("get_config");
export const setConfig = (cfg: PortalConfig) => invoke<void>("set_config", { cfg });
