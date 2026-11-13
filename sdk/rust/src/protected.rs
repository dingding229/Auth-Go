//! Language-neutral launcher evidence; never reads the Go SDK's private cache.
use crate::{b64, derive, grant, hash, random, text, Client, Error};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{fs, io::Write, path::Path};

const PREFIX: &str = "AUTHGO-PAYLOAD-PROOF-v1.";
fn mac(identity: &str, fp: &str, ticket: &str) -> Result<Vec<u8>, Error> {
    let key = derive(
        fp.as_bytes(),
        &[],
        format!("authgo/payload-proof/key/v1\0{identity}").as_bytes(),
        32,
    )?;
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|_| crate::error("SDK_CACHE_UNAVAILABLE"))?;
    m.update(format!("authgo-payload-proof-v1\0{ticket}").as_bytes());
    Ok(m.finalize().into_bytes().to_vec())
}
fn encode(identity: &str, fp: &str, ticket: &str) -> Result<String, Error> {
    Ok(format!(
        "{PREFIX}{}.{}",
        b64(ticket.as_bytes()),
        b64(&mac(identity, fp, ticket)?)
    ))
}
fn write(path: &Path, raw: &str) -> std::io::Result<()> {
    let root = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    fs::create_dir_all(root)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.is_file() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
    }
    let temp = root.join(format!(".authgo-payload-{}.tmp", hash(&random(16))));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(raw.as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp, path)
    })();
    let _ = fs::remove_file(temp);
    result
}
fn clear(root: &Path, identity: &str) {
    let context = hash(identity.as_bytes());
    let _ = fs::remove_file(root.join(format!("authgo-payload-proof-v1-{context}.cache")));
    let prefix = format!("authgo-payload-v2-{context}-");
    if let Ok(entries) = fs::read_dir(root) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(".cache") {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }
}
impl Client {
    fn protected_identity(&self) -> String {
        let endpoint = if let Some((scheme, rest)) = self.endpoint.split_once("://") {
            let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
            format!("{scheme}://{}/{}", host.to_ascii_lowercase(), path)
        } else {
            self.endpoint.clone()
        };
        format!(
            "{}\0{}\0{}\0{}",
            endpoint,
            text(&self.config, "app_key"),
            self.fp,
            hash(&self.public)
        )
    }
    pub(crate) fn clear_protected(&self) {
        if std::env::var("AUTHGO_PROTECTED").as_deref() != Ok("1") || self.memory_cache {
            return;
        }
        if let Some(root) = self.cache.parent() {
            clear(root, &self.protected_identity());
        }
    }
    pub(crate) fn save_protected(&self, ticket: &str) {
        if std::env::var("AUTHGO_PROTECTED").as_deref() != Ok("1") || self.memory_cache {
            return;
        }
        let Ok(g) = grant(
            ticket,
            &self.public,
            text(&self.config, "app_key"),
            &self.fp,
        ) else {
            return;
        };
        if g["is_trial"] == true || crate::date(&g["grace_until"]) <= crate::date(&g["issued_at"]) {
            self.clear_protected();
            return;
        }
        if let Some(root) = self.cache.parent() {
            let identity = self.protected_identity();
            if let Ok(raw) = encode(&identity, &self.fp, ticket) {
                let _ = write(
                    &root.join(format!(
                        "authgo-payload-proof-v1-{}.cache",
                        hash(identity.as_bytes())
                    )),
                    &raw,
                );
            }
        }
    }
}
// Best effort only. This blocks same-uid process inspection, not host root.
#[cfg(target_os = "linux")]
pub(crate) fn harden() {
    if std::env::var("AUTHGO_PROTECTED").as_deref() != Ok("1") {
        return;
    }
    unsafe extern "C" {
        fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    }
    // SAFETY: PR_SET_DUMPABLE takes an integer 0 and no pointers or owned resources.
    if unsafe { prctl(4, 0, 0, 0, 0) } != 0 {
        eprintln!("受保护进程无法禁用转储，继续运行；宿主机root仍可读取内存");
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn harden() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{date, decode, number};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    fn validate(raw: &str, identity: &str, fp: &str, public: &[u8], app: &str, now: i64) -> bool {
        let Some(p) = raw.strip_prefix(PREFIX) else {
            return false;
        };
        let parts: Vec<_> = p.split('.').collect();
        if parts.len() != 2 {
            return false;
        }
        let Ok(t) = decode(parts[0]) else {
            return false;
        };
        let Ok(t) = String::from_utf8(t) else {
            return false;
        };
        let Ok(actual) = decode(parts[1]) else {
            return false;
        };
        let key = derive(
            fp.as_bytes(),
            &[],
            format!("authgo/payload-proof/key/v1\0{identity}").as_bytes(),
            32,
        )
        .unwrap();
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        h.update(format!("authgo-payload-proof-v1\0{t}").as_bytes());
        if h.verify_slice(&actual).is_err() {
            return false;
        }
        grant(&t, public, app, fp).is_ok_and(|g| {
            g["is_trial"] != true && date(&g["issued_at"]) <= now && now < date(&g["grace_until"])
        })
    }
    #[test]
    fn cross_language_vector_and_instance_tamper() {
        let v: Value =
            serde_json::from_str(include_str!("../../vectors/payload-cache-v2.json")).unwrap();
        let id = text(&v, "cache_identity_utf8");
        let fp = text(&v, "fingerprint");
        let ticket = text(&v, "ticket");
        assert_eq!(encode(id, fp, ticket).unwrap(), text(&v, "proof_file_utf8"));
        let public = decode(text(&v, "proof_public_key")).unwrap();
        let app = text(&v["payload"], "app_key");
        let now = number(&v, "proof_now");
        let raw = text(&v, "proof_file_utf8");
        assert!(validate(raw, id, fp, &public, app, now));
        assert!(!validate(raw, id, "another-instance", &public, app, now));
        let parts: Vec<_> = ticket.split('.').collect();
        let raw_ticket = String::from_utf8(decode(parts[0]).unwrap())
            .unwrap()
            .replace("\"features\":{}", "\"features\":{\"tampered\":true}");
        let altered = format!("{}.{}", b64(raw_ticket.as_bytes()), parts[1]);
        let changed = format!(
            "{PREFIX}{}.{}",
            b64(altered.as_bytes()),
            b64(&mac(id, fp, ticket).unwrap())
        );
        assert!(!validate(&changed, id, fp, &public, app, now));
        // Recompute the instance MAC too: the Ed25519 signature must still fail.
        assert!(!validate(
            &encode(id, fp, &altered).unwrap(),
            id,
            fp,
            &public,
            app,
            now
        ));
    }
    #[test]
    fn refresh_outlives_initial_grace_and_refusal_cleans_both() {
        let v: Value =
            serde_json::from_str(include_str!("../../vectors/payload-cache-v2.json")).unwrap();
        let id = text(&v, "cache_identity_utf8");
        let fp = text(&v, "fingerprint");
        let public = decode(text(&v, "proof_public_key")).unwrap();
        let signing = SigningKey::from_bytes(&[0x45; 32]);
        assert_eq!(public, signing.verifying_key().as_bytes());
        let parts: Vec<_> = text(&v, "ticket").split('.').collect();
        let mut g: Value = serde_json::from_slice(&decode(parts[0]).unwrap()).unwrap();
        let original_end = date(&g["grace_until"]);
        g["issued_at"] = json!("2026-11-08T00:00:00Z");
        g["grace_until"] = json!("2026-11-09T00:00:00Z");
        let raw = serde_json::to_vec(&g).unwrap();
        let sig = signing.sign(&[b"authgo-ticket-v2\0", raw.as_slice()].concat());
        let ticket = format!("{}.{}", b64(&raw), b64(&sig.to_bytes()));
        let root = std::env::temp_dir().join(format!("authgo-proof-{}", hash(&random(16))));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "authgo-payload-proof-v1-{}.cache",
            hash(id.as_bytes())
        ));
        write(&path, text(&v, "proof_file_utf8")).unwrap();
        let now = date(&json!("2026-11-08T00:01:00Z"));
        assert!(now > original_end);
        assert!(!validate(
            &fs::read_to_string(&path).unwrap(),
            id,
            fp,
            &public,
            text(&g, "app_key"),
            now
        ));
        write(&path, &encode(id, fp, &ticket).unwrap()).unwrap();
        assert!(validate(
            &fs::read_to_string(&path).unwrap(),
            id,
            fp,
            &public,
            text(&g, "app_key"),
            now
        ));
        let key = root.join(format!(
            "authgo-payload-v2-{}-one.cache",
            hash(id.as_bytes())
        ));
        fs::write(&key, "ciphertext").unwrap();
        clear(&root, id);
        assert!(!path.exists());
        assert!(!key.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
