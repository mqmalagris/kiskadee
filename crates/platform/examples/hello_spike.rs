//! Phase 0 spike: Windows Hello user presence and a Hello-backed encryption key.
//!
//! Run with `cargo run -p kiskadee-platform --example hello_spike` and answer
//! the Hello prompts. Throwaway code: the real module lands in Phase 2.
#![allow(
    unsafe_code,
    reason = "spike: Win32 interop for the consent prompt window"
)]

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use sha2::{Digest, Sha256};
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::core::{Array, HSTRING};
    use windows_future::IAsyncOperation;

    const KEY_NAME: &str = "kiskadee-hello-spike";
    // A fixed challenge: RSA PKCS#1 v1.5 signatures are deterministic, so the
    // same challenge signed by the same Hello key yields the same bytes.
    const CHALLENGE: &[u8] = b"kiskadee/credential-key/v1";

    println!("1. Hello available?");
    let supported = KeyCredentialManager::IsSupportedAsync()?.join()?;
    println!("   supported = {supported}");
    if !supported {
        return Err("Windows Hello is not set up on this machine".into());
    }

    let request_presence = |message: &str| -> Result<
        UserConsentVerificationResult,
        Box<dyn std::error::Error>,
    > {
        let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
        // SAFETY: GetConsoleWindow has no preconditions; the HWND parents the prompt.
        let hwnd = unsafe { GetConsoleWindow() };
        // SAFETY: valid HWND (or null) and an owned HSTRING for the call's duration.
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(message))? };
        Ok(operation.join()?)
    };

    if std::env::args().any(|arg| arg == "--cancel") {
        println!("CANCEL MODE");
        println!("A. Creating the Hello key: APPROVE this prompt...");
        let created = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(KEY_NAME),
            KeyCredentialCreationOption::ReplaceExisting,
        )?
        .join()?;
        println!("   create status = {:?}", created.Status()?);
        let credential = created.Credential()?;

        println!("B. Signing: CANCEL this prompt...");
        let signed = credential
            .RequestSignAsync(&CryptographicBuffer::CreateFromByteArray(CHALLENGE)?)?
            .join()?;
        println!(
            "   sign status = {:?} (expected UserCanceled = {:?})",
            signed.Status()?,
            KeyCredentialStatus::UserCanceled
        );

        println!("C. Presence: CANCEL this prompt...");
        let presence = request_presence("kiskadee spike: please CANCEL this one")?;
        println!(
            "   presence result = {presence:?} (expected Canceled = {:?})",
            UserConsentVerificationResult::Canceled
        );

        KeyCredentialManager::DeleteAsync(&HSTRING::from(KEY_NAME))?.join()?;
        println!("Cleanup: deleted Hello key '{KEY_NAME}'");
        return Ok(());
    }

    println!("2. User presence prompt (approve it)...");
    let presence = request_presence("kiskadee spike: approve to continue")?;
    println!("   presence result = {presence:?}");
    if presence != UserConsentVerificationResult::Verified {
        return Err(format!("presence not verified: {presence:?}").into());
    }

    let derive_key = || -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))?.join()?;
        let credential = if opened.Status()? == KeyCredentialStatus::Success {
            opened.Credential()?
        } else {
            println!("   creating Hello key '{KEY_NAME}' (prompt)...");
            let created = KeyCredentialManager::RequestCreateAsync(
                &HSTRING::from(KEY_NAME),
                KeyCredentialCreationOption::FailIfExists,
            )?
            .join()?;
            if created.Status()? != KeyCredentialStatus::Success {
                return Err(format!("create failed: {:?}", created.Status()?).into());
            }
            created.Credential()?
        };
        println!("   signing challenge (prompt)...");
        let signed = credential
            .RequestSignAsync(&CryptographicBuffer::CreateFromByteArray(CHALLENGE)?)?
            .join()?;
        if signed.Status()? != KeyCredentialStatus::Success {
            return Err(format!("sign failed: {:?}", signed.Status()?).into());
        }
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&signed.Result()?, &mut signature)?;
        Ok(Sha256::digest(&signature[..]).into())
    };

    println!("3. Derive key #1 from a Hello signature");
    let key_one = derive_key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_one));
    let nonce = Nonce::from_slice(b"spike-nonce!"); // fixed nonce: spike only
    let sealed = cipher
        .encrypt(nonce, b"gmail-refresh-token".as_ref())
        .map_err(|_| "encrypt failed")?;
    println!("   sealed {} bytes", sealed.len());

    println!("4. Derive key #2 (fresh Hello prompt) and decrypt");
    let key_two = derive_key()?;
    let opened = ChaCha20Poly1305::new(Key::from_slice(&key_two))
        .decrypt(nonce, sealed.as_ref())
        .map_err(|_| "decrypt failed: keys differ")?;
    println!(
        "   keys equal = {}, plaintext = {:?}",
        key_one == key_two,
        String::from_utf8_lossy(&opened)
    );

    println!("5. Now CANCEL the next prompt to check the failure path...");
    match derive_key() {
        Ok(_) => println!("   unexpected: sign succeeded (did you approve it?)"),
        Err(error) => println!("   cancelled cleanly: {error}"),
    }

    println!("Cleanup: deleting Hello key '{KEY_NAME}'");
    KeyCredentialManager::DeleteAsync(&HSTRING::from(KEY_NAME))?.join()?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows only");
}
