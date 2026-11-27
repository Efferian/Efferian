#![allow(clippy::unwrap_used)]

use super::*;

const UUID_HEX: &str = "01890f23eab170008000000000000001";

fn fixed_keys() -> VaultKeys {
    VaultKeys::derive(Zeroizing::new(std::array::from_fn(|i| i as u8))).unwrap()
}

fn fixed_vault() -> Vault {
    fixed_keys().bind_hub(HubId::parse(&format!("hub_{UUID_HEX}")).unwrap())
}

fn account_aad() -> AccountAad {
    AccountAad {
        account_id: AccountId::parse(&format!("acc_{UUID_HEX}")).unwrap(),
        secret_version: NonZeroU64::new(7).unwrap(),
        kind: AccountKind::HttpAuth,
    }
}

fn execution_aad() -> ExecutionAad {
    ExecutionAad {
        execution_id: ExecutionId::parse(&format!("exec_{UUID_HEX}")).unwrap(),
        caller_principal_id: PrincipalId::parse(&format!("usr_{UUID_HEX}")).unwrap(),
    }
}

#[test]
fn interoperable_key_derivation_and_verifiers() {
    // Verified against Python's HMAC/SHA-256 implementation.
    let keys = fixed_keys();
    let expected_keys = [
        "24fbaea8b2b25a5217c29156816c6c72ccecc6ccc731ffac84d2850e91e705fd",
        "0a0ade330a43c2ad35f2412f7d95e1cb52934e7b30d6edf302f26fee8e60c530",
        "3d23036670df1e8f39871600f6a1fc7ecc7f2db860b310b81716883f11532d07",
        "72117fcaaccd4450009c24a37a3c14c87795413cc49de850c2f19d9332e7f688",
        "a6773bbd9edd093b9e96ceaafff59146a3c9afce10064c606bef3a1c6652f319",
    ];
    let actual_keys = [
        &keys.aead,
        &keys.token,
        &keys.enrollment,
        &keys.node,
        &keys.fingerprint,
    ];
    for (expected, actual) in expected_keys.into_iter().zip(actual_keys) {
        assert_eq!(encode_hex(actual.as_slice()), expected);
    }
    let identity = keys.expected_hub_identity();
    assert_eq!(identity.active_key_id, 1);
    assert_eq!(identity.master_key_fingerprint, expected_keys[4]);

    let secret = std::array::from_fn(|i| 0x20 + i as u8);
    for (family, prefix, expected) in [
        (
            CredentialFamily::Token,
            "tok",
            "1f0dfb38ec64109f067e2d71f8b1ca85fb883344c62fa38a310a1169b5955d46",
        ),
        (
            CredentialFamily::Enrollment,
            "enr",
            "fa58b5abb3c5ddd1955c662a43a87f5b6498e917a58f0bd6d8e8e3563136b292",
        ),
        (
            CredentialFamily::Node,
            "node",
            "85ee77a4c2ba99f9caaaf8c98dfbc5e7f0381821e893b5ed1371d0d022677024",
        ),
    ] {
        let verifier = keys
            .compute_verifier(family, &format!("{prefix}_{UUID_HEX}"), &secret)
            .unwrap();
        assert_eq!(encode_hex(verifier.as_slice()), expected);
    }
}

fn fixed_envelope(ciphertext_and_tag: &str) -> Vec<u8> {
    let wire =
        format!("454653310001000102030405060708090a0b0c0d0e0f1011121314151617{ciphertext_and_tag}");
    (0..wire.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn interoperable_account_and_execution_envelopes() {
    // Verified against libsodium's XChaCha20-Poly1305-IETF implementation.
    let vault = fixed_vault();
    let account = fixed_envelope("c4c89d02cb59c833a82091b2672c67b7ea32");
    let execution = fixed_envelope("c4c8103ed92bc39ca4cc9905a2147aab7885");
    assert_eq!(
        &*vault.open_account(&account_aad(), &account).unwrap(),
        b"v0"
    );
    assert_eq!(
        &*vault.open_execution(&execution_aad(), &execution).unwrap(),
        b"v0"
    );
    assert!(vault.open_account(&account_aad(), &execution).is_err());
    assert!(vault.open_execution(&execution_aad(), &account).is_err());
}

#[test]
fn envelope_authenticates_header_payload_and_row_identity() {
    let vault = fixed_vault();
    let aad = account_aad();
    let first = vault.seal_account(&aad, b"v0").unwrap();
    let second = vault.seal_account(&aad, b"v0").unwrap();
    assert_ne!(
        &first[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES],
        &second[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES]
    );
    assert_eq!(&first[..MAGIC.len()], MAGIC);
    assert_eq!(&*vault.open_account(&aad, &first).unwrap(), b"v0");
    assert_eq!(&*vault.open_account(&aad, &second).unwrap(), b"v0");

    for index in [0, 4, 5, HEADER_BYTES - 1, HEADER_BYTES, first.len() - 1] {
        let mut tampered = first.clone();
        tampered[index] ^= 1;
        assert!(vault.open_account(&aad, &tampered).is_err());
    }

    for wrong in [
        AccountAad {
            account_id: AccountId::new(),
            ..aad
        },
        AccountAad {
            secret_version: NonZeroU64::new(8).unwrap(),
            ..aad
        },
        AccountAad {
            kind: AccountKind::SshKey,
            ..aad
        },
        AccountAad {
            kind: AccountKind::SecretKv,
            ..aad
        },
    ] {
        assert!(vault.open_account(&wrong, &first).is_err());
    }
    assert!(
        fixed_keys()
            .bind_hub(HubId::new())
            .open_account(&aad, &first)
            .is_err()
    );
    assert!(
        VaultKeys::derive(Zeroizing::new([0; 32]))
            .unwrap()
            .bind_hub(vault.hub_id())
            .open_account(&aad, &first)
            .is_err()
    );

    let execution_aad = execution_aad();
    let envelope = vault.seal_execution(&execution_aad, b"execution").unwrap();
    for wrong in [
        ExecutionAad {
            execution_id: ExecutionId::new(),
            ..execution_aad
        },
        ExecutionAad {
            caller_principal_id: PrincipalId::new_user(),
            ..execution_aad
        },
    ] {
        assert!(vault.open_execution(&wrong, &envelope).is_err());
    }
}

#[test]
fn enforce_envelope_size_in_both_directions() {
    let vault = fixed_vault();
    let aad = account_aad();
    let empty = vault.seal_account(&aad, b"").unwrap();
    assert_eq!(empty.len(), OVERHEAD);
    assert!(vault.open_account(&aad, &empty).unwrap().is_empty());
    for length in 0..OVERHEAD {
        assert!(matches!(
            vault.open_account(&aad, &empty[..length]),
            Err(VaultError::InvalidEnvelope)
        ));
    }

    let plaintext = vec![7; MAX_WORK_BYTES - OVERHEAD + 1];
    assert!(matches!(
        vault.seal_account(&aad, &plaintext),
        Err(VaultError::PayloadTooLarge)
    ));
    let mut envelope = vault
        .seal_account(&aad, &plaintext[..plaintext.len() - 1])
        .unwrap();
    assert_eq!(envelope.len(), MAX_WORK_BYTES);
    assert_eq!(
        &*vault.open_account(&aad, &envelope).unwrap(),
        &plaintext[..plaintext.len() - 1]
    );
    envelope.push(0);
    assert!(matches!(
        vault.open_account(&aad, &envelope),
        Err(VaultError::PayloadTooLarge)
    ));
}

#[tokio::test]
async fn owned_execution_helpers_round_trip_across_offload_threshold() {
    let vault = Arc::new(fixed_vault());
    for size in [2, CRYPTO_OFFLOAD_BYTES - OVERHEAD, CRYPTO_OFFLOAD_BYTES] {
        let aad = execution_aad();
        let envelope = vault
            .seal_execution_async(aad, Zeroizing::new(vec![7; size]))
            .await
            .unwrap();
        assert_eq!(
            &*vault.open_execution_async(aad, envelope).await.unwrap(),
            &[7].repeat(size)
        );
    }
}

#[test]
fn issuing_uses_fresh_randomness_and_redacts_both_secrets() {
    let vault = fixed_vault();
    let id = TokenId::new_user_or_agent();
    let first = vault.issue_token(id).unwrap();
    let second = vault.issue_token(id).unwrap();
    assert_ne!(first.secret, second.secret);
    assert_ne!(first.verifier, second.verifier);
    assert!(
        first
            .secret
            .expose_secret()
            .starts_with(&format!("eff_{id}."))
    );
    let debug = format!("{first:?}");
    assert!(!debug.contains(first.secret.expose_secret()));
    assert!(!debug.contains(&first.verifier));
}
