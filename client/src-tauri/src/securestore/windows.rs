// Windows current-user DPAPI vault protection.

use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use zeroize::{Zeroize, Zeroizing};

use super::{Sealer, VaultError};

const MAGIC: &[u8; 5] = b"NILW\x01";

pub(crate) fn platform_sealer() -> Result<Arc<dyn Sealer>, VaultError> {
    Ok(Arc::new(DpapiSealer))
}

struct DpapiSealer;

pub(super) fn replace_file(temp: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both UTF-16 paths are NUL-terminated and remain alive for the synchronous call.
    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Sealer for DpapiSealer {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        let input = blob(plaintext)?;
        let entropy = blob(aad)?;
        let mut output = empty_blob();
        // SAFETY: input/entropy borrow valid slices for the call; output is initialized by DPAPI.
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(VaultError::Sealer(format!(
                "Windows DPAPI encryption failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let protected = copy_and_free(&mut output, false)?;
        let mut envelope = Vec::with_capacity(MAGIC.len() + protected.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&protected);
        Ok(envelope)
    }

    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if ciphertext.len() <= MAGIC.len() || &ciphertext[..MAGIC.len()] != MAGIC {
            return Err(VaultError::Authentication);
        }
        let input = blob(&ciphertext[MAGIC.len()..])?;
        let entropy = blob(aad)?;
        let mut output = empty_blob();
        // SAFETY: input/entropy borrow valid slices for the call; the optional description pointer
        // is null so DPAPI allocates only `output`, which `copy_and_free` always releases.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(VaultError::Authentication);
        }
        copy_and_free(&mut output, true).map(Zeroizing::new)
    }

    fn destroy_key(&self) -> Result<(), VaultError> {
        // Current-user DPAPI owns its root key; deleting the encrypted vault revokes this payload.
        Ok(())
    }
}

fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, VaultError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| VaultError::Sealer("DPAPI input is too large".into()))?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        // DPAPI's C API is not const-correct for input blobs; it does not mutate this buffer.
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn empty_blob() -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    }
}

fn copy_and_free(
    output: &mut CRYPT_INTEGER_BLOB,
    contains_plaintext: bool,
) -> Result<Vec<u8>, VaultError> {
    if output.cbData == 0 || output.pbData.is_null() {
        return Err(VaultError::Sealer(
            "Windows DPAPI returned an empty result".into(),
        ));
    }
    // SAFETY: successful DPAPI calls return `cbData` initialized bytes allocated by LocalAlloc.
    let bytes = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copy = bytes.to_vec();
    if contains_plaintext {
        bytes.zeroize();
    }
    // SAFETY: DPAPI documents that output.pbData must be released with LocalFree exactly once.
    let free_result = unsafe { LocalFree(output.pbData.cast::<c_void>()) };
    output.pbData = ptr::null_mut();
    output.cbData = 0;
    if !free_result.is_null() {
        let mut copy = copy;
        if contains_plaintext {
            copy.zeroize();
        }
        return Err(VaultError::Sealer(
            "Windows DPAPI buffer release failed".into(),
        ));
    }
    Ok(copy)
}
