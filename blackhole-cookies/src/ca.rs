//! Generates or loads the local root CA this module uses to terminate
//! TLS locally. See `THREAT_MODEL.md` in full before touching this file;
//! this is the one piece of this crate that, if compromised, matters
//! well beyond this crate itself.
//!
//! The CA is generated once, on first use, and persisted to disk so the
//! user only has to trust it once, not on every run: `Issuer::from_ca_cert_pem`
//! is the single load path, used identically whether the PEM files were
//! just freshly written this run or already existed from a previous one.
//!
//! The private key file is the one piece of real secret material this
//! workspace holds in memory anywhere (see the root `SECURITY.md`'s
//! `zeroize` policy, written in anticipation of exactly this case): the
//! raw PEM text is read into a `zeroize::Zeroizing<String>` and zeroized
//! immediately after `KeyPair::from_pem` has parsed it, rather than left
//! sitting in an ordinary `String` for the rest of the process's life.

use std::path::{Path, PathBuf};

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CookiesError;

const CA_COMMON_NAME: &str = "BlackHole Cookies Local CA";
/// How many leaf (per-domain) certificates the authority keeps cached in
/// memory before evicting the least-recently-used one. Matches the
/// example in hudsucker's own README; not a security-relevant number,
/// just a cache size.
const LEAF_CERT_CACHE_SIZE: usize = 1_000;

#[derive(Debug, Clone)]
pub struct CaPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

pub fn default_ca_paths() -> Result<CaPaths, CookiesError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole-cookies").ok_or_else(|| {
        CookiesError::Platform(
            "could not determine a user data directory on this platform".to_string(),
        )
    })?;
    let dir = dirs.data_dir().join("ca");
    Ok(CaPaths {
        cert_path: dir.join("hudsucker.cer"),
        key_path: dir.join("hudsucker.key"),
    })
}

/// Ensure a CA exists at `paths` (generating one if this is the first
/// run), then build the `RcgenAuthority` the proxy signs per-domain
/// certificates with. Always goes through PEM on disk, even for a
/// freshly generated CA, so "generate" and "load" share one code path
/// (see the module doc).
pub fn load_or_generate(paths: &CaPaths) -> Result<RcgenAuthority, CookiesError> {
    if !paths.cert_path.is_file() || !paths.key_path.is_file() {
        generate_and_save(paths)?;
    }

    let cert_pem = std::fs::read_to_string(&paths.cert_path)?;
    let key_pem = Zeroizing::new(std::fs::read_to_string(&paths.key_path)?);

    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|e| CookiesError::Ca(format!("failed to parse CA private key: {e}")))?;
    // `key_pem` (the raw PEM text) is zeroized here, once `key_pair` (the
    // parsed key material `rcgen`/`hudsucker` actually use from now on)
    // has been built from it; nothing below this line still needs the
    // original text form.
    drop(key_pem);

    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .map_err(|e| CookiesError::Ca(format!("failed to parse CA certificate: {e}")))?;

    Ok(RcgenAuthority::new(
        issuer,
        LEAF_CERT_CACHE_SIZE as u64,
        aws_lc_rs::default_provider(),
    ))
}

fn generate_and_save(paths: &CaPaths) -> Result<(), CookiesError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key_pair = KeyPair::generate()
        .map_err(|e| CookiesError::Ca(format!("failed to generate CA key pair: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CookiesError::Ca(format!("failed to self-sign CA certificate: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    if let Some(dir) = paths.cert_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&paths.cert_path, &cert_pem)?;
    write_private_key_file(&paths.key_path, &key_pem)?;

    Ok(())
}

#[cfg(unix)]
fn write_private_key_file(path: &Path, pem: &str) -> Result<(), CookiesError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, pem)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_file(path: &Path, pem: &str) -> Result<(), CookiesError> {
    // Windows: the file already inherits the per-user data directory's
    // own ACLs (not world-readable by default under %APPDATA%); no
    // separate chmod-equivalent is applied here. Documented as a gap
    // rather than silently assumed equivalent to the Unix 0600 case.
    std::fs::write(path, pem)?;
    Ok(())
}

/// SHA-256 fingerprint of the CA certificate's DER encoding, formatted as
/// colon-separated uppercase hex (`AA:BB:CC:...`), the conventional
/// display form. This is what `THREAT_MODEL.md` tells a user to verify
/// before trusting the certificate; see `blackhole-cookies ca-fingerprint`.
pub fn fingerprint(cert_pem: &str) -> Result<String, CookiesError> {
    let der = pem_to_der(cert_pem)?;
    let digest = Sha256::digest(&der);
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, CookiesError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64_decode(body.trim())
        .map_err(|e| CookiesError::Ca(format!("malformed CA certificate PEM: {e}")))
}

/// Minimal base64 (standard alphabet, with padding) decoder, since this
/// is the only place this crate needs one and pulling in a whole crate
/// for one decode call isn't worth it. Not a general-purpose decoder:
/// only used on a PEM body this same module just wrote or loaded.
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let bytes = bytes
        .strip_suffix(b"==")
        .unwrap_or_else(|| bytes.strip_suffix(b"=").unwrap_or(&bytes));

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk
            .iter()
            .map(|&b| value(b))
            .collect::<Option<_>>()
            .ok_or("invalid base64 character")?;
        match vals.len() {
            4 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
                out.push((vals[2] << 6) | vals[3]);
            }
            3 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
            }
            2 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
            }
            _ => return Err("invalid base64 length"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generating_then_loading_round_trips_the_same_ca() {
        let dir =
            std::env::temp_dir().join(format!("blackhole-cookies-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = CaPaths {
            cert_path: dir.join("hudsucker.cer"),
            key_path: dir.join("hudsucker.key"),
        };

        load_or_generate(&paths).expect("first call generates a CA");
        assert!(paths.cert_path.is_file());
        assert!(paths.key_path.is_file());

        let first_cert = std::fs::read_to_string(&paths.cert_path).unwrap();
        load_or_generate(&paths).expect("second call loads the same CA, not a fresh one");
        let second_cert = std::fs::read_to_string(&paths.cert_path).unwrap();
        assert_eq!(
            first_cert, second_cert,
            "a second run must not silently regenerate the CA"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "blackhole-cookies-ca-perms-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = CaPaths {
            cert_path: dir.join("hudsucker.cer"),
            key_path: dir.join("hudsucker.key"),
        };

        load_or_generate(&paths).unwrap();
        let mode = std::fs::metadata(&paths.key_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_is_stable_for_the_same_certificate() {
        let dir =
            std::env::temp_dir().join(format!("blackhole-cookies-fp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = CaPaths {
            cert_path: dir.join("hudsucker.cer"),
            key_path: dir.join("hudsucker.key"),
        };
        load_or_generate(&paths).unwrap();
        let cert_pem = std::fs::read_to_string(&paths.cert_path).unwrap();

        let a = fingerprint(&cert_pem).unwrap();
        let b = fingerprint(&cert_pem).unwrap();
        assert_eq!(a, b);
        // SHA-256 -> 32 bytes -> 32 two-hex-digit groups joined by ':'.
        assert_eq!(a.split(':').count(), 32);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_generated_cas_have_different_fingerprints() {
        let dir_a =
            std::env::temp_dir().join(format!("blackhole-cookies-fp-a-{}", std::process::id()));
        let dir_b =
            std::env::temp_dir().join(format!("blackhole-cookies-fp-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let paths_a = CaPaths {
            cert_path: dir_a.join("a.cer"),
            key_path: dir_a.join("a.key"),
        };
        let paths_b = CaPaths {
            cert_path: dir_b.join("b.cer"),
            key_path: dir_b.join("b.key"),
        };

        load_or_generate(&paths_a).unwrap();
        load_or_generate(&paths_b).unwrap();
        let fp_a = fingerprint(&std::fs::read_to_string(&paths_a.cert_path).unwrap()).unwrap();
        let fp_b = fingerprint(&std::fs::read_to_string(&paths_b.cert_path).unwrap()).unwrap();
        assert_ne!(fp_a, fp_b);

        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }
}
