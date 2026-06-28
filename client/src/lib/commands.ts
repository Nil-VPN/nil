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

export const createEmailAccount = (email: string) =>
  invoke<AnonymousAccount>("create_email_account", { email });

export const recoverAccount = (phrase: string[], recoveryCode: string) =>
  invoke<RecoverResult>("recover_account", { phrase, recoveryCode });

// Host platform — lets us route Connect to the native datapath on mobile (the OS VpnService /
// PacketTunnel) instead of the in-process loopback engine. Cached after the first call.
let platformCache: Promise<string> | null = null;
export const platform = () => {
  if (!platformCache) platformCache = invoke<string>("platform");
  return platformCache;
};
const isMobile = async () => {
  const p = await platform().catch(() => "other");
  return p === "android" || p === "ios";
};

/** Start args the native VPN plugin needs — node endpoint + pinned measurement + opaque grant.
 *  The index signature lets it pass straight to `invoke` as the plugin command payload. */
interface NativeStartArgs extends Record<string, unknown> {
  nodeHost: string;
  nodePort: number;
  serverName: string;
  measurementHex: string;
  teeName: string;
  grantHex: string;
  grantNonceHex: string;
}

// Desktop: the in-process engine brings up the real attested MASQUE tunnel (or loopback when no
// Coordinator is set). Mobile: redeem the token in the app process, then hand the resulting
// attested endpoint + grant to the native plugin, which starts the OS VpnService/PacketTunnel.
// Either way the Connect button calls one function and gets back a connection state.
export const connect = async (): Promise<ConnState> => {
  if (await isMobile()) {
    // `extension_connect` removes one token from disk, redeems it at the Coordinator, and returns
    // the attested start args (fails closed on no token / no Coordinator / bad path). The same
    // command backs the macOS system-extension build; routing macOS Connect through it lands with
    // the SE control plugin (see the macOS-SE milestones).
    const args = await invoke<NativeStartArgs>("extension_connect");
    await invoke<void>("plugin:nil-vpn|startVPN", args);
    // The OS service runs out-of-process; report connected once it has been started.
    return "connected";
  }
  return invoke<ConnState>("connect");
};

export const disconnect = async (): Promise<ConnState> => {
  if (await isMobile()) {
    await invoke<void>("plugin:nil-vpn|stopVPN");
    return "disconnected";
  }
  return invoke<ConnState>("disconnect");
};

export const status = () => invoke<ConnState>("status");

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

// Settings: operator endpoints + toggles, persisted and applied to the datapath.
export const getConfig = () => invoke<PortalConfig>("get_config");
export const setConfig = (cfg: PortalConfig) => invoke<void>("set_config", { cfg });
