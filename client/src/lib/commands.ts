// The single place the frontend calls into the Rust core. Tauri converts Rust
// snake_case command params to camelCase on the JS side, so we pass camelCase keys.
// A command that returns `Err(String)` on the Rust side rejects the promise with that
// string — callers catch it and show an error banner.

import { invoke } from "@tauri-apps/api/core";
import type { AnonymousAccount, ConnState, Location, RecoverResult } from "./types";

export const createAnonymousAccount = () =>
  invoke<AnonymousAccount>("create_anonymous_account");

export const createEmailAccount = (email: string) =>
  invoke<AnonymousAccount>("create_email_account", { email });

export const recoverAccount = (phrase: string[], recoveryCode: string) =>
  invoke<RecoverResult>("recover_account", { phrase, recoveryCode });

export const connect = () => invoke<ConnState>("connect");
export const disconnect = () => invoke<ConnState>("disconnect");
export const status = () => invoke<ConnState>("status");

export const listLocations = () => invoke<Location[]>("list_locations");
export const setTransportMode = (mode: string) =>
  invoke<void>("set_transport_mode", { mode });
export const setSplitTunnel = (enabled: boolean, apps: string[]) =>
  invoke<void>("set_split_tunnel", { enabled, apps });
export const toggleKillSwitch = (enabled: boolean) =>
  invoke<void>("toggle_kill_switch", { enabled });
