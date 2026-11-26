use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use efferian_protocol::*;
use serde_json::json;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn secret_values_round_trip_with_redacted_debug() -> Result {
    let secret = SecretString::new("fake-secret");
    assert_eq!(format!("{secret:?}"), "[REDACTED]");
    assert!(secret.ct_eq(&SecretString::new("fake-secret")));
    assert!(!secret.ct_eq(&SecretString::new("fake-secrex")));
    assert!(!secret.ct_eq(&SecretString::new("short")));
    assert_eq!(secret.len(), 11);
    assert!(!secret.is_empty());
    assert_eq!(
        serde_json::from_value::<SecretString>(json!(secret))?,
        secret
    );
    assert_eq!(secret.into_zeroizing().as_str(), "fake-secret");

    let empty_kv = AccountSecretPayload::SecretKv {
        entries: BTreeMap::new(),
    };
    assert!(empty_kv.validate().is_err());
    for name in ["", "x=y", "a\0b"] {
        let kv = AccountSecretPayload::SecretKv {
            entries: BTreeMap::from([(name.into(), SecretString::new("secret"))]),
        };
        assert!(kv.validate().is_err());
    }
    let kv = AccountSecretPayload::SecretKv {
        entries: BTreeMap::from([("ssh_key".into(), SecretString::new("fake-secret"))]),
    };
    kv.validate()?;
    assert!(kv.ct_eq(&kv.clone()));
    assert!(!format!("{kv:?}").contains("fake-secret"));
    Ok(())
}

#[test]
fn authentication_headers_use_the_secret_specific_rules() -> Result {
    for good in [
        HttpAuthSecret::Bearer {
            token: SecretString::new("token"),
        },
        HttpAuthSecret::Header {
            name: "Authorization".into(),
            value: SecretString::new("token"),
        },
        HttpAuthSecret::Header {
            name: "X-Api-Key".into(),
            value: SecretString::new("token"),
        },
        HttpAuthSecret::Basic {
            username: "user".into(),
            password: SecretString::new("token"),
        },
    ] {
        good.validate()?;
        assert!(good.ct_eq(&good.clone()));
    }
    for bad in [
        HttpAuthSecret::Bearer {
            token: SecretString::new(""),
        },
        HttpAuthSecret::Bearer {
            token: SecretString::new("a\0b"),
        },
        HttpAuthSecret::Header {
            name: "hOsT".into(),
            value: SecretString::new("token"),
        },
        HttpAuthSecret::Header {
            name: "bad name".into(),
            value: SecretString::new("token"),
        },
        HttpAuthSecret::Header {
            name: "X-Api-Key".into(),
            value: SecretString::new("a\r\nb"),
        },
        HttpAuthSecret::Basic {
            username: "user:name".into(),
            password: SecretString::new("token"),
        },
        HttpAuthSecret::Basic {
            username: "user".into(),
            password: SecretString::new("a\x7fb"),
        },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    assert!(
        serde_json::from_value::<HttpAuthSecret>(json!({"kind":"bearer","token":"a","extra":1}))
            .is_err()
    );
    Ok(())
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let Ok(len) = u8::try_from(value.len()) else {
        return Vec::new();
    };
    let mut encoded = vec![tag, len];
    encoded.extend_from_slice(value);
    encoded
}

fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let Ok(len) = u32::try_from(bytes.len()) else {
        return Vec::new();
    };
    let mut field = len.to_be_bytes().to_vec();
    field.extend_from_slice(bytes);
    field
}

fn openssh(
    cipher: &[u8],
    kdf: &[u8],
    matching_checkints: bool,
    include_private: bool,
    valid_padding: bool,
) -> Vec<u8> {
    let kind = b"ssh-ed25519";
    let public_key = [0; 32];
    let fake_private_key = [0; 64];
    let public = [ssh_string(kind), ssh_string(&public_key)].concat();
    let mut private = b"test".repeat(2);
    if !matching_checkints {
        private[0] = 0;
    }
    private.extend(ssh_string(kind));
    private.extend(ssh_string(&public_key));
    if include_private {
        private.extend(ssh_string(&fake_private_key));
    }
    private.extend(ssh_string(b"fixture"));
    let padding = (8 - private.len() % 8) % 8;
    private.extend(1..=padding as u8);
    if !valid_padding && let Some(last) = private.last_mut() {
        *last ^= 0x80;
    }
    [
        b"openssh-key-v1\0".to_vec(),
        ssh_string(cipher),
        ssh_string(kdf),
        ssh_string(&[]),
        1u32.to_be_bytes().to_vec(),
        ssh_string(&public),
        ssh_string(&private),
    ]
    .concat()
}

#[test]
fn ssh_accepts_unencrypted_well_formed_containers() -> Result {
    // These test records model container structure only.
    let pkcs8 = tlv(
        0x30,
        &[
            tlv(0x02, &[0]),
            tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])),
            tlv(0x04, &[4, 1, 0]),
        ]
        .concat(),
    );
    let rsa = tlv(0x30, &[tlv(0x02, &[0]), tlv(0x02, &[1]).repeat(8)].concat());
    let ec = tlv(0x30, &[tlv(0x02, &[1]), tlv(0x04, &[0, 0, 0])].concat());
    let ssh = openssh(b"none", b"none", true, true, true);
    for (label, bytes) in [
        ("PRIVATE KEY", pkcs8),
        ("RSA PRIVATE KEY", rsa),
        ("EC PRIVATE KEY", ec),
        ("OPENSSH PRIVATE KEY", ssh),
    ] {
        let fixture = pem(label, &bytes);
        validate_ssh_private_key_pem(&fixture)?;
        AccountSecretPayload::SshKey {
            private_key_pem: SecretString::new(fixture.clone()),
        }
        .validate()?;
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            validate_ssh_private_key_pem(&pem(label, &trailing)).is_err(),
            "{label}"
        );
        assert!(
            validate_ssh_private_key_pem(&pem(label, &bytes[..bytes.len() - 1])).is_err(),
            "{label}"
        );
    }
    Ok(())
}

#[test]
fn ssh_rejects_unsupported_encrypted_or_incomplete_keys() {
    let invalid_der = tlv(0x30, &tlv(0x02, &[0]));
    for label in ["PUBLIC KEY", "CERTIFICATE", "ENCRYPTED PRIVATE KEY"] {
        assert_eq!(
            validate_ssh_private_key_pem(&pem(label, &[1, 2, 3])),
            Err(SshKeyError::UnsupportedContainer.into())
        );
    }
    let label = "PRIVATE KEY";
    let fixture = pem(label, &invalid_der);
    assert_eq!(
        validate_ssh_private_key_pem(&fixture),
        Err(SshKeyError::InvalidDer.into())
    );
    let indefinite_der = pem(label, &[0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(
        validate_ssh_private_key_pem(&indefinite_der),
        Err(SshKeyError::InvalidDer.into())
    );
    for bad in [
        fixture.replace("END PRIVATE", "END EC PRIVATE"),
        format!("{fixture}{fixture}"),
        fixture.replace('\n', "\nProc-Type: 4,ENCRYPTED\n"),
        format!("-----BEGIN {label}-----\n====\n-----END {label}-----"),
        pem(label, &[]),
        " ".repeat(MAX_SSH_PRIVATE_KEY_BYTES + 1),
    ] {
        assert_eq!(
            validate_ssh_private_key_pem(&bad),
            Err(SshKeyError::InvalidPem.into())
        );
    }
    for bad in [
        openssh(b"aes256-ctr", b"bcrypt", true, true, true),
        openssh(b"none", b"bcrypt", true, true, true),
        openssh(b"none", b"none", false, true, true),
        openssh(b"none", b"none", true, false, true),
        openssh(b"none", b"none", true, true, false),
    ] {
        assert_eq!(
            validate_ssh_private_key_pem(&pem("OPENSSH PRIVATE KEY", &bad)),
            Err(SshKeyError::InvalidOpenSsh.into())
        );
    }
}
