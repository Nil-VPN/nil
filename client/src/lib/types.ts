// TypeScript mirrors of the Rust types returned by the Tauri commands.

export type ConnState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting";

export interface AnonymousAccount {
  account_number: string;
  recovery_phrase: string[]; // exactly 7 words
  recovery_code: string;
}

export interface RecoverResult {
  account_number: string;
  entitlement: string;
}

export interface Location {
  id: string;
  label: string;
}
