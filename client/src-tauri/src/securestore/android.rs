//! Android Keystore-backed vault protection through a private native Tauri plugin.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::plugin::PluginHandle;
use tauri::Runtime;
use zeroize::{Zeroize, Zeroizing};

use super::{Sealer, VaultError};

pub(crate) fn platform_sealer<R: Runtime>(handle: PluginHandle<R>) -> Arc<dyn Sealer> {
    Arc::new(AndroidSealer { handle })
}

struct AndroidSealer<R: Runtime> {
    handle: PluginHandle<R>,
}

#[derive(Serialize)]
struct CryptoRequest {
    data: String,
    aad: String,
}

impl Drop for CryptoRequest {
    fn drop(&mut self) {
        self.data.zeroize();
        self.aad.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoResponse {
    data: String,
}

impl Drop for CryptoResponse {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<R: Runtime> AndroidSealer<R> {
    fn invoke(&self, command: &str, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        let request = CryptoRequest {
            data: STANDARD.encode(bytes),
            aad: STANDARD.encode(aad),
        };
        let response: CryptoResponse = self
            .handle
            .run_mobile_plugin(command, request)
            .map_err(|_| VaultError::Sealer("Android Keystore operation failed".into()))?;
        STANDARD
            .decode(response.data.as_bytes())
            .map_err(|_| VaultError::Sealer("Android Keystore returned malformed data".into()))
    }
}

impl<R: Runtime> Sealer for AndroidSealer<R> {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.invoke("seal", plaintext, aad)
    }

    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.invoke("open", ciphertext, aad).map(Zeroizing::new)
    }

    fn destroy_key(&self) -> Result<(), VaultError> {
        self.handle
            .run_mobile_plugin::<()>("destroyKey", ())
            .map_err(|_| VaultError::Sealer("Android Keystore operation failed".into()))
    }
}
