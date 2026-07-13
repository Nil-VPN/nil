// TypeScript mirrors of the Rust types returned by the Tauri commands.

export type ConnState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting";

export interface AnonymousAccount {
  account_number: string;
  recovery_phrase: string[]; // exactly 12 BIP39 words (128-bit entropy + checksum)
}

export interface RecoverResult {
  account_number: string;
  entitlement: string;
}

export interface Location {
  id: string;
  label: string;
}

/** Operator endpoints + toggles (mirrors Rust `ClientConfig`; serde snake_case). */
export interface PortalConfig {
  portal_url: string;
  coordinator_url: string;
  monero_address: string;
  expected_measurement: string;
  expected_tee: string;
  kill_switch: boolean;
  node_host: string;
}
