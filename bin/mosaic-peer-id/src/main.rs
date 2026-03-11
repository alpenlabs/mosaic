#![doc = "Helper binary for generating Ed25519 signing keys and deriving Mosaic peer IDs."]

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use mosaic_net_svc::peer_id_from_signing_key;
use rand::{RngCore, rngs::OsRng};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);

    let signing_key = match (args.next().as_deref(), args.next()) {
        (None, None) => generate_signing_key(),
        (Some("--signing-key"), Some(value)) => {
            if args.next().is_some() {
                bail!(
                    "unexpected extra arguments\nusage: mosaic-peer-id [--signing-key <64-char-hex>]"
                );
            }
            decode_signing_key(&value)?
        }
        (Some("-h" | "--help"), None) => {
            print_usage();
            return Ok(());
        }
        _ => bail!("invalid arguments\nusage: mosaic-peer-id [--signing-key <64-char-hex>]"),
    };

    let peer_id = peer_id_from_signing_key(&signing_key);
    println!("signing_key_hex={}", hex::encode(signing_key.to_bytes()));
    println!("peer_id={peer_id}");
    Ok(())
}

fn generate_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn decode_signing_key(value: &str) -> Result<SigningKey> {
    let raw = hex::decode(value).context("signing key must be valid hex")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("signing key must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn print_usage() {
    println!("usage: mosaic-peer-id [--signing-key <64-char-hex>]");
    println!("  no arguments           generate a random signing key and print its peer ID");
    println!("  --signing-key <hex>    print the peer ID for an existing 32-byte signing key");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_signing_key_requires_exact_length() {
        assert!(decode_signing_key("00").is_err());
        assert!(decode_signing_key(&"00".repeat(32)).is_ok());
    }

    #[test]
    fn derived_peer_id_matches_verifying_key_bytes() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let peer_id = peer_id_from_signing_key(&signing_key);

        assert_eq!(
            peer_id.to_string(),
            hex::encode(signing_key.verifying_key().to_bytes())
        );
    }
}
