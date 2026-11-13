use crate::{b64, error, hash, random, Error};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    sync::{Mutex, OnceLock},
};
static SESSION: OnceLock<Mutex<(u32, String)>> = OnceLock::new();
static REPLACED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
static MEMORY: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
pub(crate) fn session() -> String {
    let pid = std::process::id();
    let mut value = SESSION
        .get_or_init(|| Mutex::new((pid, b64(&random(16)))))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if value.0 != pid {
        *value = (pid, b64(&random(16)));
    }
    value.1.clone()
}
pub(crate) fn mark(key: String) -> Result<(), Error> {
    REPLACED
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?
        .insert(key);
    Ok(())
}
pub(crate) fn replaced(key: &str) -> Result<bool, Error> {
    Ok(REPLACED
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?
        .contains(key))
}
pub fn detect(
    read: impl Fn(&str) -> std::io::Result<Vec<u8>>,
    env: impl Fn(&str) -> Option<String>,
) -> bool {
    if let Some(force) = env("AUTHGO_CONTAINER") {
        if force == "0" || force == "1" {
            return force == "1";
        }
    }
    for path in ["/.dockerenv", "/run/.containerenv"] {
        if read(path).is_ok() {
            return true;
        }
    }
    read("/proc/1/cgroup").is_ok_and(|raw| {
        ["docker", "containerd", "kubepods", "libpod"]
            .iter()
            .any(|x| String::from_utf8_lossy(&raw).contains(x))
    })
}
pub fn fingerprint(id: &str) -> String {
    hash(format!("authgo/instance/v1\0{id}").as_bytes())
}
fn read(path: &Path) -> std::io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() != 64 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o777 != 0o600 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
    }
    let id = fs::read_to_string(path)?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(id)
}
pub(crate) fn identity(dir: &Path) -> Result<(String, bool), Error> {
    let persist = || -> std::io::Result<String> {
        if dir.as_os_str().is_empty() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        fs::create_dir_all(dir)?;
        let target = dir.join("instance-id");
        if target.try_exists()? {
            return read(&target);
        }
        let temp = dir.join(format!(".instance-{}", b64(&random(16))));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut f = options.open(&temp)?;
            f.write_all(
                random(32)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .as_bytes(),
            )?;
            f.sync_all()?;
            match fs::hard_link(&temp, &target) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
                _ => (),
            }
            read(&target)
        })();
        let _ = fs::remove_file(temp);
        result
    };
    if let Ok(id) = persist() {
        return Ok((id, false));
    }
    let mut memory = MEMORY
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
    Ok((
        memory
            .entry(format!("{}\0{}", std::process::id(), dir.display()))
            .or_insert_with(|| {
                random(32)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
            .clone(),
        true,
    ))
}
