//! Synchronous Auth Go v2 SDK. No credentials are included in error messages.
pub mod codes;
pub mod container;
mod guard;
mod protected;
mod watermark;
pub use guard::{Completion, Guard, GuardOptions, OnChange, EXIT_LICENSE};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};
#[derive(Debug, Clone)]
pub struct Error {
    pub code: String,
    pub authenticated: bool,
    pub latest_version: String,
    pub latest_entitled_version: String,
    pub cause: Option<Box<Error>>,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code == "SDK_INVALID_CONFIG" {
            write!(f, "{}: 请在后台重新复制接入配置", self.code)
        } else {
            write!(f, "{}", self.code)
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}
fn error(c: &str) -> Error {
    Error {
        code: c.into(),
        authenticated: false,
        cause: None,
        latest_version: String::new(),
        latest_entitled_version: String::new(),
    }
}
impl Error {
    pub fn code(&self) -> &str {
        &self.code
    }
    fn refusal(&self) -> bool {
        self.authenticated && !temporary(&self.code)
    }
}
pub fn temporary(c: &str) -> bool {
    matches!(
        c,
        "INTERNAL_ERROR"
            | "RATE_LIMITED"
            | "REPLAY_DETECTED"
            | "TIMESTAMP_INVALID"
            | "SIGNATURE_INVALID"
            | "INVALID_REQUEST"
            | "PAYLOAD_INVALID"
    )
}
pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let b = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| error("SDK_RESPONSE_INVALID"))?;
    if b64(&b) != s {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    Ok(b)
}
pub fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; n];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .map_err(|_| error("SDK_RESPONSE_INVALID"))?;
    Ok(out)
}
fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    OsRng.fill_bytes(&mut b);
    b
}
pub fn seal(key: &[u8], n: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if n.len() != 12 {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| error("SDK_RESPONSE_INVALID"))?
        .encrypt(Nonce::from_slice(n), Payload { msg: data, aad })
        .map_err(|_| error("SDK_RESPONSE_INVALID"))
}
pub fn open(key: &[u8], n: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if n.len() != 12 {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| error("SDK_RESPONSE_INVALID"))?
        .decrypt(Nonce::from_slice(n), Payload { msg: data, aad })
        .map_err(|_| error("SDK_RESPONSE_INVALID"))
}
pub fn canonical(v: &Value) -> String {
    serde_json::to_string(v)
        .unwrap_or_default()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
// Duplicate object keys must not be accepted as an alternative signed spelling.
pub fn parse(raw: &[u8]) -> Result<Value, Error> {
    fn unique(raw: &[u8]) -> Result<(), Error> {
        let mut strings = Vec::new();
        let mut stack: Vec<std::collections::HashSet<String>> = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            match raw[i] {
                b'{' => {
                    stack.push(Default::default());
                    if stack.len() > 100 {
                        return Err(error("SDK_RESPONSE_INVALID"));
                    }
                }
                b'}' => {
                    stack.pop();
                }
                b'"' => {
                    let start = i;
                    i += 1;
                    while i < raw.len() {
                        if raw[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if raw[i] == b'"' {
                            break;
                        }
                        i += 1
                    }
                    if i >= raw.len() {
                        return Err(error("SDK_RESPONSE_INVALID"));
                    }
                    strings.push((start, i + 1));
                    let mut j = i + 1;
                    while j < raw.len() && raw[j].is_ascii_whitespace() {
                        j += 1
                    }
                    if j < raw.len() && raw[j] == b':' {
                        let s: String = serde_json::from_slice(&raw[start..i + 1])
                            .map_err(|_| error("SDK_RESPONSE_INVALID"))?;
                        if let Some(set) = stack.last_mut() {
                            if !set.insert(s) {
                                return Err(error("SDK_RESPONSE_INVALID"));
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1
        }
        Ok(())
    }
    unique(raw)?;
    serde_json::from_slice(raw).map_err(|_| error("SDK_RESPONSE_INVALID"))
}
pub fn padding(raw: &[u8]) -> Vec<u8> {
    let len = 4096.max((raw.len() + 4).div_ceil(512) * 512);
    let mut p = random(len);
    p[..4].copy_from_slice(&(raw.len() as u32).to_be_bytes());
    p[4..raw.len() + 4].copy_from_slice(raw);
    p
}
pub fn unpad(b: &[u8]) -> Result<Vec<u8>, Error> {
    if b.len() < 4 {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    let n = u32::from_be_bytes(
        b[..4]
            .try_into()
            .map_err(|_| error("SDK_RESPONSE_INVALID"))?,
    ) as usize;
    if n == 0 || n + 4 > b.len() || b.len() != 4096.max((n + 4).div_ceil(512) * 512) {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    Ok(b[4..n + 4].to_vec())
}
pub fn verify(public: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(public) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(data, &sig).is_ok()
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn number(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or(0)
}
fn date(v: &Value) -> i64 {
    v.as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp())
        .unwrap_or(i64::MAX)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs() as i64)
        .unwrap_or(0)
}
fn command(p: &str, args: &[&str]) -> Result<String, Error> {
    let mut child = std::process::Command::new(p)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
    let start = std::time::Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?
            .is_some()
        {
            break;
        }
        if start.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error("SDK_FINGERPRINT_UNAVAILABLE"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
    if !output.status.success() {
        return Err(error("SDK_FINGERPRINT_UNAVAILABLE"));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().into())
        .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))
}

pub fn identity_hash(machine: &str, mac: &str, cpu: &str) -> Result<String, Error> {
    let mac = mac.trim().to_lowercase().replace('-', ":");
    let parts: Vec<_> = mac.split(':').collect();
    if machine.trim().is_empty()
        || cpu.trim().is_empty()
        || ![6, 8].contains(&parts.len())
        || parts
            .iter()
            .any(|x| x.len() != 2 || u8::from_str_radix(x, 16).is_err())
    {
        return Err(error("SDK_FINGERPRINT_UNAVAILABLE"));
    }
    Ok(hash(
        format!(
            "authgo/fingerprint/v1\0{}\0{}\0{}",
            machine.trim().to_lowercase(),
            mac,
            cpu.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        )
        .as_bytes(),
    ))
}
pub fn validate_key(key: &str) -> Result<(), Error> {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let p: Vec<_> = key.split('-').collect();
    if p.len() != 5
        || p[0].is_empty()
        || p[0].len() > 16
        || p[1..].iter().any(|s| s.len() != 5)
        || p.iter().any(|s| s.bytes().any(|c| !ALPHABET.contains(&c)))
    {
        return Err(error("INVALID_LICENSE_KEY"));
    }
    let mut check = p[0].len() % 32;
    for c in format!("{}{}{}{}{}", p[0], p[1], p[2], p[3], &p[4][..4]).bytes() {
        let index = ALPHABET
            .iter()
            .position(|v| *v == c)
            .ok_or_else(|| error("INVALID_LICENSE_KEY"))?;
        check = (check * 17 + index) % 32;
    }
    if p[4].as_bytes()[4] != ALPHABET[check] {
        return Err(error("INVALID_LICENSE_KEY"));
    }
    Ok(())
}
pub fn parse_linux_cpu(raw: &str) -> String {
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if ["model name", "Hardware", "cpu model"].contains(&k.trim()) && !v.trim().is_empty() {
                return v.trim().into();
            }
        }
    }
    let (mut implementer, mut part, mut uarch) = (String::new(), String::new(), String::new());
    let (mut seen, mut done) = (false, false);
    for line in raw.lines() {
        if line.trim().is_empty() && seen {
            done = true;
        }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k == "uarch" && uarch.is_empty() {
                uarch = v.into();
            }
            if !done {
                if k == "CPU implementer" {
                    seen = true;
                    if implementer.is_empty() {
                        implementer = v.split_whitespace().collect::<String>().to_lowercase();
                    }
                }
                if k == "CPU part" {
                    seen = true;
                    if part.is_empty() {
                        part = v.split_whitespace().collect::<String>().to_lowercase();
                    }
                }
            }
        }
    }
    if !implementer.is_empty() && !part.is_empty() {
        format!("arm:{implementer}:{part}")
    } else {
        uarch
    }
}

pub fn fingerprint() -> Result<String, Error> {
    if std::env::consts::OS == "linux" {
        let machine = fs::read_to_string("/etc/machine-id")
            .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
            .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let cpu = fs::read_to_string("/proc/cpuinfo")
            .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let cpu = parse_linux_cpu(&cpu);
        let route = fs::read_to_string("/proc/net/route").unwrap_or_default();
        let preferred = route
            .lines()
            .filter_map(|s| {
                let f: Vec<_> = s.split_whitespace().collect();
                if f.len() > 3 && f[1] == "00000000" {
                    Some(f[0])
                } else {
                    None
                }
            })
            .next()
            .unwrap_or("");
        let mut items = BTreeMap::new();
        for item in
            fs::read_dir("/sys/class/net").map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?
        {
            let p = item
                .map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?
                .path();
            let flags = u32::from_str_radix(
                fs::read_to_string(p.join("flags"))
                    .unwrap_or_default()
                    .trim()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);
            if flags & 8 != 0 {
                continue;
            }
            let mac = fs::read_to_string(p.join("address")).unwrap_or_default();
            if mac.replace([':', '0', '\n'], "").is_empty() {
                continue;
            }
            let index = fs::read_to_string(p.join("ifindex"))
                .unwrap_or_default()
                .trim()
                .parse::<u32>()
                .unwrap_or(u32::MAX);
            let up = flags & 1 != 0;
            items.insert(
                index,
                (
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    mac,
                    up,
                ),
            );
        }
        let nic = items
            .values()
            .find(|v| v.0 == preferred)
            .or_else(|| items.values().find(|v| v.2))
            .or_else(|| items.values().next())
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        return identity_hash(&machine, &nic.1, &cpu);
    }
    // Use native OS commands, never hash a substitute such as a hostname.
    if std::env::consts::OS == "macos" {
        let raw = command("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?;
        let machine = raw
            .lines()
            .find(|s| s.contains("\"IOPlatformUUID\""))
            .and_then(|s| s.split_once('='))
            .map(|(_, s)| s.trim().trim_matches('"'))
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let cpu = command("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|_| command("/usr/sbin/sysctl", &["-n", "hw.model"]))?;
        let route = command("/sbin/route", &["-n", "get", "default"]).unwrap_or_default();
        let preferred = route
            .lines()
            .find_map(|s| s.trim().strip_prefix("interface:"))
            .map(str::trim)
            .unwrap_or("");
        let raw = command("/sbin/ifconfig", &["-a", "-v"])?;
        let mut items = BTreeMap::new();
        let mut current = None;
        for line in raw.lines() {
            if !line.starts_with(char::is_whitespace) {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                let index = tokens
                    .iter()
                    .position(|v| *v == "index")
                    .and_then(|i| tokens.get(i + 1))
                    .and_then(|s| s.parse::<u32>().ok());
                let name = tokens
                    .first()
                    .map(|s| s.trim_end_matches(':'))
                    .unwrap_or("");
                current = index.map(|index| {
                    (
                        index,
                        name.to_string(),
                        line.contains("<UP,") || line.contains(",UP,") || line.contains(",UP>"),
                    )
                });
            }
            if let Some(mac) = line.trim().strip_prefix("ether ") {
                if let Some((index, name, up)) = &current {
                    let mac = mac.split_whitespace().next().unwrap_or("").to_string();
                    if !mac.replace([':', '0'], "").is_empty() {
                        items.insert(*index, (name.clone(), mac, *up));
                    }
                }
            }
        }
        let nic = items
            .values()
            .find(|v| v.0 == preferred)
            .or_else(|| items.values().find(|v| v.2))
            .or_else(|| items.values().next())
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        return identity_hash(machine, &nic.1, &cpu);
    }
    if std::env::consts::OS == "windows" {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let reg = format!("{root}\\System32\\reg.exe");
        let raw = command(
            &reg,
            &[
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
                "/reg:64",
            ],
        )?;
        let machine = raw
            .lines()
            .find_map(|l| l.split_once("REG_SZ"))
            .map(|(_, s)| s.trim())
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let raw_cpu = command(
            &reg,
            &[
                "query",
                r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "/v",
                "ProcessorNameString",
            ],
        )?;
        let cpu = raw_cpu
            .lines()
            .find_map(|l| l.split_once("REG_SZ"))
            .map(|(_, s)| s.trim())
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let ps = format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        let preferred=command(&ps,&["-NoProfile","-NonInteractive","-Command","Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex"]).unwrap_or_default();
        let data=command(&ps,&["-NoProfile","-NonInteractive","-Command","ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,MacAddress,Status)"])?;
        let data: Value =
            serde_json::from_str(&data).map_err(|_| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        let mut nics = data
            .as_array()
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?
            .iter()
            .filter(|n| {
                !text(n, "MacAddress")
                    .replace(['-', ':', '0'], "")
                    .is_empty()
            })
            .collect::<Vec<_>>();
        nics.sort_by_key(|n| number(n, "ifIndex"));
        let nic = nics
            .iter()
            .find(|n| number(n, "ifIndex").to_string() == preferred)
            .or_else(|| nics.iter().find(|n| text(n, "Status") == "Up"))
            .or_else(|| nics.first())
            .ok_or_else(|| error("SDK_FINGERPRINT_UNAVAILABLE"))?;
        return identity_hash(machine, text(nic, "MacAddress"), cpu);
    }
    Err(error("SDK_FINGERPRINT_UNAVAILABLE"))
}
#[derive(Clone)]
pub struct Options {
    pub root_cert_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub version: String,
    pub clock: fn() -> i64,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            fingerprint: None,
            root_cert_der: None,
            cache_dir: None,
            version: String::new(),
            clock: now,
        }
    }
}
struct State {
    data: Value,
    offline_ticket: String,
    offline_until: i64,
    online_ticket: String,
    online_until: i64,
}
pub struct Client {
    config: Value,
    endpoint: String,
    public: Vec<u8>,
    gateway: [u8; 32],
    fp: String,
    cache: PathBuf,
    memory_cache: bool,
    cache_warning: Mutex<Option<String>>,
    aad: Vec<u8>,
    cache_key: Vec<u8>,
    options: Options,
    state: Arc<Mutex<State>>,
    agent: ureq::Agent,
}
#[derive(Clone)]
pub struct ResultData {
    pub is_trial: bool,
    pub maintenance_until: Option<String>,
    pub latest_entitled_version: String,
    pub data: Value,
    pub status: String,
    pub offline: bool,
    pub reason: String,
    pub remaining_seconds: i64,
    pub heartbeat_interval: i64,
    pub cache_warning: Option<String>,
    ticket: String,
    end: i64,
}
fn heartbeat_interval(data: &Value, cached: i64) -> i64 {
    if (1..=3600).contains(&cached) {
        return cached;
    }
    if data["floating"] == true {
        let span = date(&data["lease_expires_at"]).saturating_sub(date(&data["issued_at"]));
        return ((span.clamp(1, 7200) + 1) / 2).clamp(1, 3600);
    }
    number(data, "next_check_in").clamp(1, 3600)
}
impl ResultData {
    fn with_heartbeat(mut self, cached: i64) -> Self {
        self.heartbeat_interval = heartbeat_interval(&self.data, cached);
        self
    }
    pub fn ticket(&self) -> &str {
        &self.ticket
    }
}
fn grant(ticket: &str, public: &[u8], app: &str, fp: &str) -> Result<Value, Error> {
    let p: Vec<_> = ticket.split('.').collect();
    if p.len() != 2 {
        return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
    }
    let raw = decode(p[0])?;
    if !verify(
        public,
        &[b"authgo-ticket-v2\0", raw.as_slice()].concat(),
        &decode(p[1])?,
    ) {
        return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
    }
    let g = parse(&raw)?;
    if number(&g, "v") != 2
        || text(&g, "app_key") != app
        || text(&g, "status") != "active"
        || number(&g, "license_id") <= 0
        || text(&g, "device_hash") != hash(fp.as_bytes())
        || decode(text(&g, "challenge"))?.len() != 32
        || !(1..=86400).contains(&number(&g, "next_check_in"))
        || date(&g["grace_until"]) < date(&g["issued_at"])
    {
        return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
    }
    Ok(g)
}
impl Client {
    /// Stable identity of this client, independent of license bindings.
    pub fn identity(&self) -> &str {
        &self.fp
    }
    pub fn new(config: &str) -> Result<Self, Error> {
        Self::with_options(config, Options::default())
    }
    pub fn with_options(config: &str, options: Options) -> Result<Self, Error> {
        let setup = || -> Result<_, Error> {
            if !config.starts_with("authgo2.") || config.len() > 32768 {
                return Err(error("SDK_INVALID_CONFIG"));
            }
            let c = parse(&decode(&config[8..])?)?;
            if c.as_object()
                .ok_or_else(|| error("SDK_INVALID_CONFIG"))?
                .keys()
                .any(|k| {
                    !["url", "app_key", "app_secret", "public_key", "gateway_key"]
                        .contains(&k.as_str())
                })
            {
                return Err(error("SDK_INVALID_CONFIG"));
            }
            for k in ["url", "app_key", "app_secret", "public_key", "gateway_key"] {
                if text(&c, k).is_empty() {
                    return Err(error("SDK_INVALID_CONFIG"));
                }
            }
            let u = text(&c, "url");
            if !valid_url(u, false) {
                return Err(error("SDK_INVALID_CONFIG"));
            }
            let public = STANDARD
                .decode(text(&c, "public_key"))
                .map_err(|_| error("SDK_INVALID_CONFIG"))?;
            let gateway: [u8; 32] = decode(text(&c, "gateway_key"))?
                .try_into()
                .map_err(|_| error("SDK_INVALID_CONFIG"))?;
            if public.len() != 32 {
                return Err(error("SDK_INVALID_CONFIG"));
            }
            Ok((c, public, gateway))
        };
        let (c, public, gateway) = setup().map_err(|_| error("SDK_INVALID_CONFIG"))?;
        let container = container::detect(|p| fs::read(p), |k| std::env::var(k).ok());
        let root = options.cache_dir.clone().unwrap_or_else(|| {
            std::env::var("AUTHGO_CACHE_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    if container {
                        PathBuf::from("/var/lib/authgo")
                    } else {
                        cache_root()
                            .join("authgo")
                            .join(hash(text(&c, "app_key").as_bytes()))
                    }
                })
        });
        let mut memory_cache = root.as_os_str().is_empty();
        let mut cache_warning = None;
        let fp = if let Some(fp) = &options.fingerprint {
            fp.to_lowercase()
        } else if let Ok(id) = std::env::var("AUTHGO_INSTANCE_ID").and_then(|s| {
            if s.is_empty() {
                Err(std::env::VarError::NotPresent)
            } else {
                Ok(s)
            }
        }) {
            container::fingerprint(&id)
        } else if container {
            let (id, memory) = container::identity(&root)?;
            memory_cache = memory;
            if memory {
                cache_warning = Some("此实例重启后是新实例，没有断连宽限".into());
            }
            container::fingerprint(&id)
        } else {
            fingerprint()?
        };
        if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(error("SDK_INVALID_CONFIG"));
        }
        let mut endpoint = text(&c, "url").trim_end_matches('/').to_string();
        if !endpoint.ends_with("/api/v1/client") {
            endpoint.push_str("/api/v1/client")
        }
        let aad = format!(
            "authgo/rust/cache/v2\0{}\0{}\0{}",
            endpoint,
            text(&c, "app_key"),
            fp
        )
        .into_bytes();
        let cache_key = derive(
            text(&c, "app_secret").as_bytes(),
            &Sha256::digest(&aad),
            b"authgo/multi/cache/key",
            32,
        )?;
        let cache = root.join(format!("{}.cache", hash(&aad)));
        let data = (!memory_cache)
            .then(|| fs::metadata(&cache).ok())
            .flatten()
            .filter(|m| m.is_file() && m.len() <= 16 * 1024 * 1024)
            .and_then(|_| fs::read(&cache).ok())
            .filter(|b| b.len() >= 28 && b.len() <= 16 * 1024 * 1024)
            .and_then(|b| open(&cache_key, &b[..12], &b[12..], &aad).ok())
            .and_then(|b| parse(&b).ok())
            .unwrap_or_else(|| json!({}));
        let mut builder = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(10));
        if let Some(cert) = options.root_cert_der.clone() {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(cert))
                .map_err(|_| error("SDK_INVALID_CONFIG"))?;
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            builder = builder.tls_config(Arc::new(tls));
        }
        let agent = builder.build();
        Ok(Self {
            config: c,
            endpoint,
            public,
            gateway,
            fp,
            cache,
            memory_cache,
            cache_warning: Mutex::new(cache_warning),
            aad,
            cache_key,
            options,
            state: Arc::new(Mutex::new(State {
                data,
                offline_ticket: String::new(),
                offline_until: 0,
                online_ticket: String::new(),
                online_until: 0,
            })),
            agent,
        })
    }
    fn save(&self, s: &State) -> Result<(), Error> {
        if self.memory_cache {
            return Ok(());
        }
        let dir = self
            .cache
            .parent()
            .ok_or_else(|| error("SDK_CACHE_UNAVAILABLE"))?;
        fs::create_dir_all(dir).map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        let n = random(12);
        let raw = [
            n.clone(),
            seal(
                &self.cache_key,
                &n,
                canonical(&s.data).as_bytes(),
                &self.aad,
            )?,
        ]
        .concat();
        let temp = dir.join(format!("{}.tmp", b64(&random(12))));
        let mut opt = fs::OpenOptions::new();
        opt.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opt.mode(0o600);
        }
        let mut f = opt
            .open(&temp)
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        f.write_all(&raw)
            .and_then(|_| f.sync_all())
            .and_then(|_| fs::rename(&temp, &self.cache))
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))
    }
    fn save_warning(&self, s: &State) {
        if self.memory_cache {
            return;
        }
        let warning = self
            .save(s)
            .err()
            .map(|_| "无法保存本地缓存，重启后没有断连宽限".into());
        if let Ok(mut current) = self.cache_warning.lock() {
            *current = warning;
        }
    }
    fn revoke_cache(&self, s: &mut State) {
        self.clear_protected();
        self.clear_payload_keys();
        s.data["ticket"] = json!("");
        s.data["seed"] = json!("");
        s.data["refused"] = json!(true);
        if self.save(s).is_err() {
            let _ = fs::remove_file(&self.cache);
        }
    }
    fn body(&self, s: &State) -> Value {
        json!({"instance_session":container::session(),"license_key":s.data["key"],"activation_token":s.data["token"].as_str().unwrap_or(""),"device_fingerprint":self.fp,"client_version":self.options.version,"hostname":"","os":os_name()})
    }
    fn request(&self, op: &str, mut body: Value) -> Result<(Value, String), Error> {
        let challenge = b64(&random(32));
        let nonce = b64(&random(32));
        let ts = (self.options.clock)().to_string();
        if body.is_object() {
            body["challenge"] = json!(challenge)
        }
        let raw = if body.is_null() {
            String::new()
        } else {
            canonical(&body)
        };
        let mut m =
            <Hmac<Sha256> as Mac>::new_from_slice(text(&self.config, "app_secret").as_bytes())
                .map_err(|_| error("SDK_INVALID_CONFIG"))?;
        m.update(format!("{op}{ts}{nonce}{}", hash(raw.as_bytes())).as_bytes());
        let sig = m
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let inner = canonical(
            &json!({"app_key":self.config["app_key"],"op":op,"timestamp":ts,"nonce":nonce,"signature":sig,"body":body}),
        );
        let private = StaticSecret::random_from_rng(OsRng);
        let ep = b64(PublicKey::from(&private).as_bytes());
        let k = &hash(&self.gateway)[..16];
        let aad = format!("authgo-gateway-v2\0{k}\0{ep}").into_bytes();
        let shared = private.diffie_hellman(&PublicKey::from(self.gateway));
        if shared.as_bytes() == &[0; 32] {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let salt = Sha256::digest(&aad);
        let n = random(12);
        let ct = seal(
            &derive(shared.as_bytes(), &salt, b"authgo/v2/request", 32)?,
            &n,
            &padding(inner.as_bytes()),
            &aad,
        )?;
        let nn = b64(&n);
        let cc = b64(&ct);
        let packet = canonical(&json!({"v":2,"k":k,"e":ep,"n":nn,"c":cc}));
        let res = self
            .agent
            .post(&format!("{}/gateway", self.endpoint))
            .set("Content-Type", "application/json")
            .send_string(&packet)
            .map_err(map_http)?;
        if res.status() != 200 {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let mut data = Vec::new();
        res.into_reader()
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|_| error("SDK_RESPONSE_INVALID"))?;
        if data.len() > 2 * 1024 * 1024 {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let outer = parse(&data)?;
        if outer
            .as_object()
            .is_none_or(|o| o.len() != 2 || !o.contains_key("n") || !o.contains_key("c"))
        {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let response_aad = [
            aad.as_slice(),
            format!("\0{}", hash(format!("{nn}.{cc}").as_bytes())).as_bytes(),
        ]
        .concat();
        let env = parse(&unpad(&open(
            &derive(shared.as_bytes(), &salt, b"authgo/v2/response", 32)?,
            &decode(text(&outer, "n"))?,
            &decode(text(&outer, "c"))?,
            &response_aad,
        )?)?)?;
        let signature = STANDARD
            .decode(text(&env, "signature"))
            .map_err(|_| error("SDK_RESPONSE_SIGNATURE_INVALID"))?;
        if !verify(
            &self.public,
            canonical(&json!({"code":env["code"],"data":env["data"],"ts":env["ts"]})).as_bytes(),
            &signature,
        ) {
            return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
        }
        if text(&env, "nonce") != nonce || text(&env["data"], "request_nonce") != nonce {
            return Err(error("SDK_RESPONSE_NONCE_INVALID"));
        }
        if (number(&env, "ts") - (self.options.clock)()).abs() > 300 {
            return Err(error("SDK_RESPONSE_TIMESTAMP_INVALID"));
        }
        if text(&env, "code") != "OK" {
            return Err(Error {
                code: text(&env, "code").into(),
                authenticated: true,
                latest_version: text(&env["data"], "latest_version").into(),
                latest_entitled_version: text(&env["data"], "latest_entitled_version").into(),
                cause: None,
            });
        }
        Ok((env["data"].clone(), challenge))
    }
    fn g(&self, t: &str) -> Result<Value, Error> {
        grant(t, &self.public, text(&self.config, "app_key"), &self.fp)
    }
    fn validity(&self, g: &Value, s: &State) -> Result<(), Error> {
        let now = (self.options.clock)();
        if now + 300 < number(&s.data, "observed") {
            return Err(error("SDK_CLOCK_ROLLBACK"));
        }
        if !g["starts_at"].is_null() && now < date(&g["starts_at"]) {
            return Err(error("LICENSE_NOT_STARTED"));
        }
        if now >= date(&g["expires_at"]) {
            return Err(error("LICENSE_EXPIRED"));
        }
        Ok(())
    }
    fn result(
        &self,
        g: Value,
        ticket: String,
        _seed: Vec<u8>,
        status: &str,
        end: i64,
        reason: String,
    ) -> ResultData {
        ResultData {
            is_trial: g["is_trial"] == true,
            maintenance_until: g["maintenance_until"].as_str().map(str::to_owned),
            latest_entitled_version: text(&g, "latest_entitled_version").into(),
            cache_warning: self
                .cache_warning
                .lock()
                .ok()
                .and_then(|warning| warning.clone()),
            heartbeat_interval: heartbeat_interval(&g, 0),
            data: g,
            status: status.into(),
            offline: status != "online",
            reason,
            remaining_seconds: end.saturating_sub((self.options.clock)()).max(0),
            ticket,
            end,
        }
    }
    fn authorization(&self, op: &str, key: Option<&str>) -> Result<ResultData, Error> {
        if let Some(key) = key {
            validate_key(key)?;
        }
        let mut s = self
            .state
            .lock()
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        let op = if op == "check" {
            if text(&s.data, "key") == key.unwrap_or("") && !text(&s.data, "token").is_empty() {
                "verify"
            } else {
                "activate"
            }
        } else {
            op
        };
        self.ensure_instance(if op == "activate" {
            key.unwrap_or("")
        } else {
            text(&s.data, "key")
        })?;
        let op = if op == "verify" {
            if let Ok(g) = self.g(text(&s.data, "ticket")) {
                if g["floating"] == true && (self.options.clock)() >= date(&g["lease_expires_at"]) {
                    "heartbeat"
                } else {
                    op
                }
            } else {
                op
            }
        } else {
            op
        };
        let previous = s.data.clone();
        if op == "activate" {
            if text(&s.data, "key") != key.unwrap_or("") {
                let old = s.data.clone();
                s.data = json!({"trial_key":old["trial_key"],"observed":old["observed"]})
            }
            s.data["key"] = json!(key.unwrap_or(""));
        } else if text(&s.data, "token").is_empty() {
            return Err(error("SDK_NOT_ACTIVATED"));
        }
        let response = self
            .request(op, {
                let mut input = self.body(&s);
                if op == "deactivate" {
                    input
                        .as_object_mut()
                        .ok_or_else(|| error("SDK_RESPONSE_INVALID"))?
                        .remove("instance_session");
                }
                if op == "activate" {
                    input["activation_token"] = json!("")
                };
                input
            })
            .and_then(|(d, ch)| {
                if op != "deactivate" {
                    let g = self.g(text(&d, "ticket"))?;
                    if g["license_id"] != d["license_id"]
                        || g["next_check_in"] != d["next_check_in"]
                    {
                        return Err(error("SDK_RESPONSE_INVALID"));
                    }
                    if text(&g, "challenge") != ch {
                        return Err(error("SDK_RESPONSE_NONCE_INVALID"));
                    }
                    if (date(&g["issued_at"]) - (self.options.clock)()).abs() > 300 {
                        return Err(error("SDK_RESPONSE_TIMESTAMP_INVALID"));
                    }
                    let seed = decode(text(&d, "unlock_seed"))?;
                    if seed.len() != 32 || hash(&seed) != text(&g, "unlock_hash") {
                        return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
                    }
                }
                if op != "deactivate" {
                    let g = self.g(text(&d, "ticket"))?;
                    if g["floating"] == true
                        && (g["lease_expires_at"].is_null()
                            || (self.options.clock)() >= date(&g["lease_expires_at"]))
                    {
                        return Err(error("LEASE_EXPIRED"));
                    }
                    self.validity(
                        &g,
                        &State {
                            data: json!({}),
                            offline_ticket: String::new(),
                            offline_until: 0,
                            online_ticket: String::new(),
                            online_until: 0,
                        },
                    )?;
                }
                Ok((d, ch))
            });
        let response = match response {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.refusal() {
                    self.clear_protected();
                    self.clear_payload_keys();
                }
                if e.authenticated && e.code == "INSTANCE_REPLACED" {
                    s.data = previous;
                    container::mark(self.instance_key(if op == "activate" {
                        key.unwrap_or("")
                    } else {
                        text(&s.data, "key")
                    }))?;
                    s.online_until = 0;
                    s.offline_until = 0;
                    return Err(e);
                }
                if op == "activate" && text(&previous, "key") != key.unwrap_or("") {
                    s.data = previous;
                    return Err(e);
                }
                if op == "activate" && e.refusal() {
                    s.data["token"] = json!("");
                    self.revoke_cache(&mut s);
                    return Err(e);
                }
                if op == "verify" || op == "heartbeat" {
                    s.online_until = 0;
                    if e.refusal() {
                        self.revoke_cache(&mut s);
                        return Err(e);
                    }
                    if self
                        .g(text(&s.data, "ticket"))
                        .is_ok_and(|g| g["is_trial"] == true)
                    {
                        return Err(error("SDK_GRACE_EXPIRED"));
                    }
                    let g = match self.g(text(&s.data, "ticket")) {
                        Ok(g) if s.data["refused"] != true && g["is_trial"] != true => g,
                        _ => return Err(e),
                    };
                    if hash(&decode(text(&s.data, "seed"))?) != text(&g, "unlock_hash") {
                        return Err(e);
                    }
                    let now = (self.options.clock)();
                    if now + 300 < number(&s.data, "observed") {
                        return Err(error("SDK_CLOCK_ROLLBACK"));
                    }
                    s.data["observed"] = json!(number(&s.data, "observed").max(now));
                    self.save(&s)?;
                    self.validity(&g, &s)?;
                    s.data["observed"] = json!(number(&s.data, "observed").max(now));
                    self.save_warning(&s);
                    let end = date(&g["grace_until"]).min(date(&g["expires_at"]));
                    s.offline_ticket = text(&s.data, "ticket").into();
                    s.offline_until = end;
                    if now < end {
                        return Ok(self
                            .result(
                                g,
                                text(&s.data, "ticket").into(),
                                decode(text(&s.data, "seed"))?,
                                "grace",
                                end,
                                e.to_string(),
                            )
                            .with_heartbeat(number(&s.data, "heartbeat_interval")));
                    }
                    return Err(Error {
                        code: "SDK_GRACE_EXPIRED".into(),
                        authenticated: false,
                        cause: Some(Box::new(e)),
                        latest_version: String::new(),
                        latest_entitled_version: String::new(),
                    });
                }
                Err(e)
            }
        }?;
        let (d, ch) = response;
        if op == "deactivate" {
            if d["deactivated"] != true {
                return Err(error("SDK_RESPONSE_INVALID"));
            }
            s.data["ticket"] = json!("");
            s.data["seed"] = json!("");
            s.data["token"] = json!("");
            s.data["refused"] = json!(true);
            self.clear_payload_keys();
            self.save(&s)?;
            return Ok(self.result(d, String::new(), vec![], "deactivated", 0, String::new()));
        }
        let g = self.g(text(&d, "ticket"))?;
        if text(&g, "challenge") != ch {
            return Err(error("SDK_RESPONSE_NONCE_INVALID"));
        }
        if (date(&g["issued_at"]) - (self.options.clock)()).abs() > 300 {
            return Err(error("SDK_RESPONSE_TIMESTAMP_INVALID"));
        }
        let seed = decode(text(&d, "unlock_seed"))?;
        if seed.len() != 32 || hash(&seed) != text(&g, "unlock_hash") {
            return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
        }
        self.validity(
            &g,
            &State {
                data: json!({}),
                offline_ticket: String::new(),
                offline_until: 0,
                online_ticket: String::new(),
                online_until: 0,
            },
        )?;
        if op == "activate" {
            let t = text(&d, "activation_token");
            if !t.starts_with("act_") || t.len() != 47 {
                return Err(error("SDK_RESPONSE_INVALID"));
            }
            s.data["token"] = d["activation_token"].clone()
        }
        s.offline_ticket.clear();
        s.offline_until = 0;
        s.online_ticket = text(&d, "ticket").into();
        s.online_until = (self.options.clock)() + number(&g, "next_check_in");
        s.data["heartbeat_interval"] =
            json!(heartbeat_interval(&g, number(&d, "heartbeat_interval")));
        s.data["ticket"] = d["ticket"].clone();
        if let Some(data) = s.data.as_object_mut() {
            data.remove("status");
            data.remove("availability");
            data.remove("guard");
        }
        s.data["seed"] = d["unlock_seed"].clone();
        s.data["refused"] = json!(false);
        s.data["payload_no_cache"] =
            json!(g["is_trial"] == true || date(&g["grace_until"]) <= date(&g["issued_at"]));
        if s.data["payload_no_cache"] == true {
            self.clear_payload_keys();
        }
        s.data["observed"] = json!((self.options.clock)().max(date(&g["issued_at"])));
        self.save_protected(text(&d, "ticket"));
        self.save_warning(&s);
        let end = date(&g["grace_until"])
            .max(s.online_until)
            .min(date(&g["expires_at"]))
            .min(if g["floating"] == true {
                date(&g["lease_expires_at"])
            } else {
                i64::MAX
            });
        Ok(self
            .result(
                g,
                text(&d, "ticket").into(),
                seed,
                "online",
                end,
                String::new(),
            )
            .with_heartbeat(number(&s.data, "heartbeat_interval")))
    }
    #[doc(hidden)]
    pub fn guard_check(&self, key: &str) -> Result<ResultData, Error> {
        if !key.is_empty() {
            return self.check(key);
        }
        let mut key = {
            let s = self
                .state
                .lock()
                .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            text(&s.data, "trial_key").to_owned()
        };
        if key.is_empty() {
            let (data, challenge) = self
                .request("trial", json!({"device_fingerprint":self.fp}))
                .inspect_err(|e| {
                    if e.refusal() {
                        self.clear_protected();
                        self.clear_payload_keys();
                    }
                })?;
            if text(&data, "challenge") != challenge {
                return Err(error("SDK_RESPONSE_NONCE_INVALID"));
            }
            key = text(&data, "license_key").to_owned();
            validate_key(&key)?;
            let mut s = self
                .state
                .lock()
                .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            s.data["trial_key"] = json!(key);
            self.save_warning(&s);
        }
        self.check(&key)
    }
    pub fn check(&self, key: &str) -> Result<ResultData, Error> {
        self.authorization("check", Some(key))
    }

    pub fn activate(&self, key: &str) -> Result<ResultData, Error> {
        self.authorization("activate", Some(key))
    }
    pub fn verify(&self) -> Result<ResultData, Error> {
        self.authorization("verify", None)
    }
    pub fn heartbeat(&self) -> Result<ResultData, Error> {
        self.authorization("heartbeat", None)
    }
    fn instance_key(&self, key: &str) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.endpoint,
            text(&self.config, "app_key"),
            self.fp,
            hash(&self.public),
            container::session(),
            key
        )
    }
    fn ensure_instance(&self, key: &str) -> Result<(), Error> {
        if container::replaced(&self.instance_key(key))? {
            return Err(error("INSTANCE_REPLACED"));
        }
        Ok(())
    }
    pub fn release_seat(&self) -> Result<(), Error> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        if text(&s.data, "ticket").is_empty()
            || self.g(text(&s.data, "ticket"))?["floating"] != true
        {
            return Ok(());
        }
        match self.request("release-seat", self.body(&s)) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.refusal() {
                    self.clear_protected();
                    self.clear_payload_keys();
                }
                if e.authenticated && e.code == "INSTANCE_REPLACED" {
                    container::mark(self.instance_key(text(&s.data, "key")))?;
                    s.online_until = 0;
                    s.offline_until = 0;
                } else if e.refusal() {
                    self.revoke_cache(&mut s);
                }
                Err(e)
            }
        }
    }
    pub fn deactivate(&self) -> Result<(), Error> {
        self.authorization("deactivate", None).map(|_| ())
    }
    pub fn validate(&self, ticket: &str) -> Result<(), Error> {
        let s = self
            .state
            .lock()
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        self.ensure_instance(text(&s.data, "key"))?;
        if s.data["refused"] == true {
            return Err(error("SDK_NOT_ACTIVATED"));
        }
        let g = self.g(ticket)?;
        self.validity(&g, &s)?;
        if g["floating"] == true
            && (g["lease_expires_at"].is_null()
                || (self.options.clock)() >= date(&g["lease_expires_at"]))
            && !(s.offline_ticket == ticket && (self.options.clock)() < s.offline_until)
        {
            return Err(error("LEASE_EXPIRED"));
        }
        if (self.options.clock)() < date(&g["grace_until"])
            || s.online_ticket == ticket && (self.options.clock)() < s.online_until
        {
            return Ok(());
        }
        Err(error("SDK_GRACE_EXPIRED"))
    }
    pub fn announcements(&self) -> Result<Value, Error> {
        self.request("announcement", Value::Null)
            .map(|(d, _)| d["items"].clone())
    }
    pub fn check_update(&self, current: &str) -> Result<Value, Error> {
        let s = self
            .state
            .lock()
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        if text(&s.data, "token").is_empty() {
            return Err(error("SDK_NOT_ACTIVATED"));
        }
        let mut body = self.body(&s);
        body["current_version"] = json!(current);
        body["client_version"] = json!(current);
        let (mut d, _) = self.request("update.check", body)?;
        if let Some(data) = d.as_object_mut() {
            data.retain(|key, _| {
                [
                    "available",
                    "docker_image",
                    "docker_pull",
                    "version",
                    "changelog",
                    "mandatory",
                    "published_at",
                    "maintenance_until",
                    "latest_entitled_version",
                    "renewal_required",
                ]
                .contains(&key.as_str())
            });
        }
        Ok(d)
    }
}
fn map_http(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(_, _) => error("SDK_RESPONSE_INVALID"),
        ureq::Error::Transport(e) => {
            use std::error::Error as _;
            let mut source = e.source();
            while let Some(s) = source {
                if s.downcast_ref::<rustls::Error>().is_some() {
                    return error("SDK_RESPONSE_INVALID");
                }
                source = s.source();
            }
            error("SDK_NETWORK_ERROR")
        }
    }
}
fn valid_url(u: &str, https_only: bool) -> bool {
    if u.contains(['@', '#'])
        || !https_only && u.contains(['?', '%'])
        || u.split('/').any(|s| s == "." || s == "..")
    {
        return false;
    }
    let Ok(url) = url::Url::parse(u) else {
        return false;
    };
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    !https_only
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

fn cache_root() -> PathBuf {
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library/Caches")
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
    }
}
fn os_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

/// Validated public payload document. The public manifest remains part of envelope AAD.
/// This raw API never launches native code; the protected Go stub owns execution.
#[derive(Clone, Debug)]
pub struct RawPayload {
    document: Value,
    files: Vec<PayloadFile>,
    manifest: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct PayloadFile {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub size: u64,
}
fn payload_invalid() -> Error {
    error("PAYLOAD_INVALID")
}
fn payload_object<'a>(
    v: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, Error> {
    let obj = v.as_object().ok_or_else(payload_invalid)?;
    if required.iter().any(|k| !obj.contains_key(*k))
        || obj
            .keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(payload_invalid());
    }
    Ok(obj)
}
fn payload_text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v[key].as_str().ok_or_else(payload_invalid)
}
fn payload_uint(v: &Value, limit: u64) -> Result<u64, Error> {
    if !v.is_number() {
        return Err(payload_invalid());
    }
    let token = v.to_string();
    let normalized = if token == "-0" { "0" } else { &token };
    if normalized.is_empty() || !normalized.bytes().all(|b| b.is_ascii_digit()) {
        return Err(payload_invalid());
    }
    let n = normalized.parse::<u64>().map_err(|_| payload_invalid())?;
    if n > limit {
        return Err(payload_invalid());
    }
    Ok(n)
}
fn payload_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn payload_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn payload_unhex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() & 1 != 0 || !payload_hex(s, s.len()) {
        return Err(payload_invalid());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| payload_invalid()))
        .collect()
}
fn payload_semver(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let mut plus = s.split('+');
    let core = plus.next().unwrap_or("");
    let build = plus.next();
    if plus.next().is_some() {
        return false;
    }
    let mut dash = core.splitn(2, '-');
    let nums: Vec<_> = dash.next().unwrap_or("").split('.').collect();
    if nums.len() != 3
        || nums.iter().any(|n| {
            n.is_empty()
                || n.len() > 1 && n.starts_with('0')
                || !n.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return false;
    }
    for (numeric, identifiers) in [(true, dash.next()), (false, build)] {
        if let Some(ids) = identifiers {
            if ids.split('.').any(|id| {
                id.is_empty()
                    || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || numeric
                        && id.len() > 1
                        && id.starts_with('0')
                        && id.bytes().all(|b| b.is_ascii_digit())
            }) {
                return false;
            }
        }
    }
    true
}
fn payload_https(s: &str) -> bool {
    if s.bytes().any(|b| b < 32 || b == 127) {
        return false;
    }
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return false;
    }
    if let Some((_, query)) = rest.split_once('?') {
        if !query.split('#').next().unwrap_or("").is_empty() {
            return false;
        }
    }
    if let Some((_, fragment)) = rest.split_once('#') {
        if !fragment.is_empty() {
            return false;
        }
    }
    let authority_path = rest.split(['?', '#']).next().unwrap_or("");
    let raw = authority_path.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len()
                || !raw[i + 1].is_ascii_hexdigit()
                || !raw[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            if i < host.len() {
                let Ok(code) = u8::from_str_radix(&authority_path[i + 1..i + 3], 16) else {
                    return false;
                };
                if code < 128 && code != 37 {
                    return false;
                }
            }
            i += 2;
        }
        i += 1;
    }
    if host.starts_with('[') {
        let Some(end) = host.rfind(']') else {
            return false;
        };
        if end <= 1 {
            return false;
        }
        let suffix = &host[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':') || !suffix[1..].bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
    } else {
        if host.contains('[') {
            return false;
        }
        if let Some((left, port)) = host.rsplit_once(':') {
            if left.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
    }
    host.bytes()
        .all(|b| b >= 128 || b.is_ascii_alphanumeric() || b"_.~!$&'()*+,;=:[]<>\"%-".contains(&b))
}
fn payload_lp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
impl RawPayload {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let run = || -> Result<Self, Error> {
            if raw.len() > 65536 {
                return Err(payload_invalid());
            }
            let p = parse(raw)?;
            payload_object(
                &p,
                &[
                    "v", "app_key", "version", "built_at", "key_id", "config", "manifest",
                    "envelope",
                ],
                &[],
            )?;
            let v = payload_uint(&p["v"], 2)?;
            if v != 2 {
                return Err(payload_invalid());
            }
            let app = payload_text(&p, "app_key")?;
            let version = payload_text(&p, "version")?;
            let built = payload_text(&p, "built_at")?;
            let id = payload_text(&p, "key_id")?;
            if app.is_empty()
                || app.len() > 256
                || id.len() > 128
                || !payload_name(id)
                || !payload_semver(version)
            {
                return Err(payload_invalid());
            }
            if built.len() != 20
                || !built.is_ascii()
                || built.as_bytes()[10] != b'T'
                || built.as_bytes()[19] != b'Z'
                || chrono::NaiveDateTime::parse_from_str(built, "%Y-%m-%dT%H:%M:%SZ")
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .ok()
                    .as_deref()
                    != Some(built)
                || &built[17..19] == "60"
            {
                return Err(payload_invalid());
            }
            let config = payload_text(&p, "config")?;
            if config.len() > 32768 || !config.starts_with("authgo2.") {
                return Err(payload_invalid());
            }
            let c = parse(&decode(&config[8..])?)?;
            payload_object(
                &c,
                &["url", "app_key", "app_secret", "public_key", "gateway_key"],
                &[],
            )?;
            if payload_text(&c, "app_key")? != app
                || payload_text(&c, "app_secret")?.is_empty()
                || !payload_https(payload_text(&c, "url")?)
            {
                return Err(payload_invalid());
            }
            let public = payload_text(&c, "public_key")?;
            let pk = STANDARD.decode(public).map_err(|_| payload_invalid())?;
            if pk.len() != 32
                || STANDARD.encode(&pk) != public
                || decode(payload_text(&c, "gateway_key")?)?.len() != 32
            {
                return Err(payload_invalid());
            }
            let manifest = decode(payload_text(&p, "manifest")?)?;
            if manifest.len() > 8 << 20 {
                return Err(payload_invalid());
            }
            let m = parse(&manifest)?;
            payload_object(&m, &["files"], &[])?;
            let files = m["files"].as_array().ok_or_else(payload_invalid)?;
            if files.is_empty() || files.len() > 65535 {
                return Err(payload_invalid());
            }
            let mut names = std::collections::HashSet::new();
            let mut metadata = 0;
            let mut out = Vec::new();
            for (i, f) in files.iter().enumerate() {
                let shape = payload_object(
                    f,
                    &["name", "kind", "path", "size", "chunk_size", "encoding"],
                    &["python_version", "main_class", "architecture"],
                )?;
                for (k, value) in shape {
                    if k != "size" && k != "chunk_size" && !value.is_string() {
                        return Err(payload_invalid());
                    }
                }
                let name = payload_text(f, "name")?;
                let kind = payload_text(f, "kind")?;
                let path = payload_text(f, "path")?;
                let encoding = payload_text(f, "encoding")?;
                let size = payload_uint(&f["size"], (i64::MAX / 2) as u64)?;
                if !payload_name(name)
                    || name.len() > 128
                    || !names.insert(name.to_owned())
                    || path != format!("{i:08}.agc")
                    || payload_uint(&f["chunk_size"], 1048576)? != 1048576
                {
                    return Err(payload_invalid());
                }
                if kind == "watermark" {
                    if v != 2
                        || name != "__authgo_watermark"
                        || encoding != "raw"
                        || !(1..=8388608).contains(&size)
                        || shape.len() != 6
                    {
                        return Err(payload_invalid());
                    }
                    metadata += 1;
                } else {
                    if v == 2 && name == "__authgo_watermark" {
                        return Err(payload_invalid());
                    }
                    let expected = match kind {
                        "python" | "php" | "dotnet" => "tar",
                        "node" | "java" | "protect" => "raw",
                        _ => return Err(payload_invalid()),
                    };
                    if encoding != expected
                        || kind == "python" && text(f, "python_version").is_empty()
                        || kind == "protect"
                            && !["amd64", "arm64"].contains(&text(f, "architecture"))
                    {
                        return Err(payload_invalid());
                    }
                }
                out.push(PayloadFile {
                    name: name.into(),
                    kind: kind.into(),
                    path: path.into(),
                    size,
                });
            }
            if v == 2 && (metadata != 1 || files.len() < 2) {
                return Err(payload_invalid());
            }
            payload_object(&p["envelope"], &["e", "n", "c"], &[])?;
            for (k, n) in [("e", 32), ("n", 12), ("c", 48)] {
                if decode(payload_text(&p["envelope"], k)?)?.len() != n {
                    return Err(payload_invalid());
                }
            }
            Ok(Self {
                document: p,
                files: out,
                manifest,
            })
        };
        run().map_err(|_| payload_invalid())
    }
    pub fn version(&self) -> u64 {
        self.document["v"].as_u64().unwrap_or(0)
    }
    pub fn files(&self) -> &[PayloadFile] {
        &self.files
    }
    pub fn to_json(&self) -> Value {
        self.document.clone()
    }
    fn aad(&self) -> Vec<u8> {
        let mut out = format!("authgo-payload-envelope-v{}\0", self.version()).into_bytes();
        for k in ["app_key", "version", "built_at", "key_id", "config"] {
            payload_lp(&mut out, text(&self.document, k));
        }
        out.extend_from_slice(&Sha256::digest(&self.manifest));
        out
    }
    pub fn payload_binding(&self) -> Vec<u8> {
        let mut out = self.aad();
        for k in ["e", "n", "c"] {
            out.extend_from_slice(&decode(text(&self.document["envelope"], k)).unwrap_or_default());
        }
        Sha256::digest(out).to_vec()
    }
    fn rewrap_aad(&self, ephemeral: &[u8], challenge: &[u8]) -> Result<Vec<u8>, Error> {
        if ephemeral.len() != 32 || challenge.len() != 32 {
            return Err(payload_invalid());
        }
        let mut out = format!("authgo-payload-rewrap-v{}\0", self.version()).into_bytes();
        for k in ["app_key", "version", "built_at", "key_id"] {
            payload_lp(&mut out, text(&self.document, k));
        }
        out.extend_from_slice(&Sha256::digest(&self.manifest));
        out.extend_from_slice(ephemeral);
        out.extend_from_slice(challenge);
        Ok(out)
    }
    fn cache_label(&self, fp: &str) -> Vec<u8> {
        let mut out = format!("authgo-payload-cache-v{}\0", self.version()).into_bytes();
        for s in [
            text(&self.document, "app_key"),
            fp,
            text(&self.document, "key_id"),
            text(&self.document, "version"),
        ] {
            payload_lp(&mut out, s);
        }
        out.extend_from_slice(&Sha256::digest(&self.manifest));
        out.extend_from_slice(&self.payload_binding());
        out
    }
    fn valid_material(&self, value: &[u8]) -> bool {
        self.version() == 2 && value.len() == 64 && value[32..].iter().any(|b| *b != 0)
    }
}
/// Parses original public payload JSON; duplicate/unknown keys and malformed metadata fail closed.
pub fn parse_payload(raw: &[u8]) -> Result<RawPayload, Error> {
    RawPayload::parse(raw)
}
fn payload_timestamp(value: &Value, required: bool) -> Result<(), Error> {
    if value.is_null() && !required {
        return Ok(());
    }
    let raw = value
        .as_str()
        .ok_or_else(|| error("SDK_RESPONSE_INVALID"))?;
    chrono::DateTime::parse_from_rfc3339(raw).map_err(|_| error("SDK_RESPONSE_INVALID"))?;
    Ok(())
}
fn payload_response_watermark(value: &Value) -> Result<Vec<u8>, Error> {
    let s = value
        .as_str()
        .ok_or_else(|| error("SDK_RESPONSE_INVALID"))?;
    if !payload_hex(s, 64) || s.bytes().all(|b| b == b'0') {
        return Err(error("SDK_RESPONSE_INVALID"));
    }
    payload_unhex(s).map_err(|_| error("SDK_RESPONSE_INVALID"))
}

// Owned temporary secrets wipe on every error path; returned material belongs to the caller.
struct PayloadSecret(Vec<u8>);
impl Drop for PayloadSecret {
    fn drop(&mut self) {
        for b in &mut self.0 {
            // SAFETY: b exclusively borrows a live, initialized byte owned by this buffer.
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
struct PayloadCacheMaterial {
    path: PathBuf,
    key: PayloadSecret,
    aad: Vec<u8>,
}
impl Client {
    fn payload_identity(&self) -> String {
        let endpoint = if let Some((scheme, rest)) = self.endpoint.split_once("://") {
            let at = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                rest[..at].to_ascii_lowercase(),
                &rest[at..]
            )
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
    fn payload_cache_material(
        &self,
        p: &RawPayload,
        g: &Value,
        disabled: bool,
    ) -> Result<PayloadCacheMaterial, Error> {
        if disabled || self.memory_cache {
            return Err(error("SDK_CACHE_UNAVAILABLE"));
        }
        let now = (self.options.clock)();
        if !g["issued_at"].is_string() || !g["grace_until"].is_string() {
            return Err(error("SDK_CACHE_INVALID"));
        }
        let issued = date(&g["issued_at"]);
        let grace = date(&g["grace_until"]);
        if g["is_trial"] == true
            || grace <= issued
            || now >= grace
            || issued > now.saturating_add(300)
        {
            return Err(error("SDK_GRACE_EXPIRED"));
        }
        if !g["starts_at"].is_null() && now < date(&g["starts_at"]) {
            return Err(error("LICENSE_NOT_STARTED"));
        }
        if now >= date(&g["expires_at"]) {
            return Err(error("LICENSE_EXPIRED"));
        }
        let id =
            payload_uint(&g["license_id"], u64::MAX).map_err(|_| error("SDK_CACHE_INVALID"))?;
        let seed = text(g, "unlock_hash");
        if id == 0 || seed.len() != 64 {
            return Err(error("SDK_CACHE_INVALID"));
        }
        let seed = PayloadSecret(
            payload_unhex(&seed.to_ascii_lowercase()).map_err(|_| error("SDK_CACHE_INVALID"))?,
        );
        let label = p.cache_label(&self.fp);
        let digest = Sha256::digest(&label);
        let key = derive(
            &seed.0,
            &[],
            &[b"authgo-unlock-v2\0".as_slice(), &label].concat(),
            32,
        )?;
        let root = self
            .cache
            .parent()
            .ok_or_else(|| error("SDK_CACHE_UNAVAILABLE"))?;
        let path = root.join(format!(
            "authgo-payload-v{}-{}-{}.cache",
            p.version(),
            hash(self.payload_identity().as_bytes()),
            hash(&label)
        ));
        let mut aad = format!("authgo-payload-cache-file-v{}\0", p.version()).into_bytes();
        aad.extend_from_slice(&digest);
        aad.extend_from_slice(&id.to_be_bytes());
        Ok(PayloadCacheMaterial {
            path,
            key: PayloadSecret(key),
            aad,
        })
    }
    fn clear_payload_keys(&self) {
        if self.memory_cache {
            return;
        }
        if let Some(root) = self.cache.parent() {
            if let Ok(entries) = fs::read_dir(root) {
                let context = hash(self.payload_identity().as_bytes());
                let prefix = format!("authgo-payload-v2-{context}-");
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with(prefix.as_str()) && name.ends_with(".cache") {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
    fn save_payload_material(&self, p: &RawPayload, g: &Value, disabled: bool, value: &[u8]) {
        if !p.valid_material(value) {
            return;
        }
        let save = || -> Result<(), Error> {
            let m = self.payload_cache_material(p, g, disabled)?;
            let nonce = random(12);
            let raw = format!(
                "AUTHGO-PAYLOAD-CACHE-v{}.{}",
                p.version(),
                b64(&[nonce.clone(), seal(&m.key.0, &nonce, value, &m.aad)?].concat())
            );
            let root = m
                .path
                .parent()
                .ok_or_else(|| error("SDK_CACHE_UNAVAILABLE"))?;
            fs::create_dir_all(root).map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            if fs::symlink_metadata(&m.path).is_ok_and(|m| !m.is_file()) {
                return Err(error("SDK_CACHE_UNAVAILABLE"));
            }
            let temp = root.join(format!(".authgo-payload-{}.tmp", b64(&random(16))));
            let write = || -> std::io::Result<()> {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                #[cfg(not(unix))]
                {
                    return Err(std::io::ErrorKind::Unsupported.into());
                }
                let mut out = options.open(&temp)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    out.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                out.write_all(raw.as_bytes())?;
                out.sync_all()?;
                drop(out);
                fs::rename(&temp, &m.path)
            };
            let result = write();
            let _ = fs::remove_file(&temp);
            result.map_err(|_| error("SDK_CACHE_UNAVAILABLE"))
        };
        let _ = save();
    }
    fn load_payload_material(
        &self,
        p: &RawPayload,
        g: &Value,
        disabled: bool,
    ) -> Result<Vec<u8>, Error> {
        let m = self.payload_cache_material(p, g, disabled)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let checked = |meta: &fs::Metadata| {
                meta.is_file()
                    && meta.mode() & 0o7777 == 0o600
                    && meta.len() <= 256
                    && meta.ino() != 0
            };
            let before =
                fs::symlink_metadata(&m.path).map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            if !checked(&before) {
                return Err(error("SDK_CACHE_UNAVAILABLE"));
            }
            #[cfg(target_os = "linux")]
            let flags = 0x20000 | 0x800; // O_NOFOLLOW | O_NONBLOCK
            #[cfg(target_os = "macos")]
            let flags = 0x100 | 0x4;
            let mut source = fs::OpenOptions::new()
                .read(true)
                .custom_flags(flags)
                .open(&m.path)
                .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            let opened = source
                .metadata()
                .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            let same = |a: &fs::Metadata, b: &fs::Metadata| {
                checked(a)
                    && checked(b)
                    && a.dev() == b.dev()
                    && a.ino() == b.ino()
                    && a.len() == b.len()
            };
            if !same(&before, &opened) {
                return Err(error("SDK_CACHE_INVALID"));
            }
            let mut raw = Vec::new();
            Read::by_ref(&mut source)
                .take(257)
                .read_to_end(&mut raw)
                .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            let after =
                fs::symlink_metadata(&m.path).map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
            if !same(&opened, &after) || raw.len() > 256 {
                return Err(error("SDK_CACHE_INVALID"));
            }
            let prefix = format!("AUTHGO-PAYLOAD-CACHE-v{}.", p.version());
            let text = std::str::from_utf8(&raw).map_err(|_| error("SDK_CACHE_INVALID"))?;
            let encrypted = decode(
                text.strip_prefix(prefix.as_str())
                    .ok_or_else(|| error("SDK_CACHE_INVALID"))?,
            )
            .map_err(|_| error("SDK_CACHE_INVALID"))?;
            if encrypted.len() != 92 {
                return Err(error("SDK_CACHE_INVALID"));
            }
            let value = PayloadSecret(
                open(&m.key.0, &encrypted[..12], &encrypted[12..], &m.aad)
                    .map_err(|_| error("SDK_CACHE_INVALID"))?,
            );
            if !p.valid_material(&value.0) {
                return Err(error("SDK_CACHE_INVALID"));
            }
            Ok(value.0.clone())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = m;
            Err(error("SDK_CACHE_UNAVAILABLE"))
        }
    }
    /// Returns K32 only, including for v2. Caller must wipe the returned key.
    pub fn unlock_payload(&self, p: &RawPayload) -> Result<Vec<u8>, Error> {
        let value = PayloadSecret(self.unlock_payload_material(p)?);
        Ok(value.0[..32].to_vec())
    }
    // Only loaders inside the SDK may obtain signed watermark material. Native execution is not implemented here.
    fn unlock_payload_material(&self, p: &RawPayload) -> Result<Vec<u8>, Error> {
        if text(&p.document, "app_key") != text(&self.config, "app_key") {
            return Err(payload_invalid());
        }
        let mut s = self
            .state
            .lock()
            .map_err(|_| error("SDK_CACHE_UNAVAILABLE"))?;
        let ticket = text(&s.data, "ticket").to_owned();
        if ticket.is_empty()
            || s.data["refused"] == true
            || text(&s.data, "token").is_empty()
            || s.online_ticket != ticket && s.offline_ticket != ticket
        {
            return Err(error("SDK_NOT_ACTIVATED"));
        }
        self.ensure_instance(text(&s.data, "key"))?;
        let old = self.g(&ticket)?;
        self.validity(&old, &s)?;
        let seed = PayloadSecret(decode(text(&s.data, "seed"))?);
        if seed.0.len() != 32 || hash(&seed.0) != text(&old, "unlock_hash") {
            return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
        }
        let disabled = s.data["payload_no_cache"] == true;
        if s.offline_ticket == ticket && s.online_until == 0 {
            return self.load_payload_material(p, &old, disabled);
        }
        let secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral = PublicKey::from(&secret);
        let mut body = self.body(&s);
        body.as_object_mut()
            .ok_or_else(payload_invalid)?
            .retain(|k, _| {
                [
                    "license_key",
                    "activation_token",
                    "device_fingerprint",
                    "instance_session",
                ]
                .contains(&k.as_str())
            });
        body["payload"] = p.to_json();
        body["ephemeral_public_key"] = json!(b64(ephemeral.as_bytes()));
        let (data, challenge) = match self.request("payload.unlock", body) {
            Ok(response) => response,
            Err(e) => {
                if e.refusal() {
                    self.clear_payload_keys();
                    if e.code == "INSTANCE_REPLACED" {
                        container::mark(self.instance_key(text(&s.data, "key")))?;
                        s.online_until = 0;
                        s.offline_until = 0;
                    } else {
                        self.revoke_cache(&mut s);
                    }
                    return Err(e);
                }
                return self.load_payload_material(p, &old, disabled).or(Err(e));
            }
        };
        // Everything below is a freshly signed reply: never fall back to cached material.
        let fresh = self.g(text(&data, "ticket"))?;
        for k in ["issued_at", "grace_until"] {
            payload_timestamp(&fresh[k], true)?;
        }
        for k in ["starts_at", "expires_at"] {
            payload_timestamp(&fresh[k], false)?;
        }
        payload_timestamp(&data["grace_until"], true)?;
        payload_timestamp(&data["expires_at"], false)?;
        if fresh["floating"] == true {
            payload_timestamp(&fresh["lease_expires_at"], true)?;
        }
        for k in [
            "license_id",
            "status",
            "expires_at",
            "features",
            "next_check_in",
            "grace_until",
            "heartbeat_interval",
            "satisfied_methods",
            "ticket",
            "unlock_seed",
        ] {
            if data.get(k).is_none() {
                return Err(error("SDK_RESPONSE_INVALID"));
            }
        }
        let methods = data["satisfied_methods"]
            .as_array()
            .ok_or_else(|| error("SDK_RESPONSE_INVALID"))?;
        let mut unique = std::collections::HashSet::new();
        if data["license_id"] != fresh["license_id"]
            || fresh["license_id"] != old["license_id"]
            || data["next_check_in"] != fresh["next_check_in"]
            || text(&fresh, "challenge") != challenge
            || text(&data, "status") != "active"
            || !data["features"].is_object()
            || !(1..=3600).contains(&number(&data, "heartbeat_interval"))
            || !methods.iter().any(|m| m == "KEY")
            || methods.iter().any(|m| {
                m.as_str()
                    .is_none_or(|m| !["KEY", "FLOATING"].contains(&m) || !unique.insert(m))
            })
        {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        if methods.iter().any(|m| m == "FLOATING") {
            payload_timestamp(&data["lease_expires_at"], true)?;
        }
        let now = (self.options.clock)();
        if date(&fresh["issued_at"]).abs_diff(now) > 300 {
            return Err(error("SDK_RESPONSE_TIMESTAMP_INVALID"));
        }
        self.validity(&fresh, &s)?;
        if fresh["floating"] == true && now >= date(&fresh["lease_expires_at"]) {
            return Err(error("LEASE_EXPIRED"));
        }
        if now >= date(&data["expires_at"])
            || methods.iter().any(|m| m == "FLOATING")
                && (data["lease_expires_at"].is_null() || now >= date(&data["lease_expires_at"]))
        {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let fresh_seed = PayloadSecret(decode(text(&data, "unlock_seed"))?);
        if fresh_seed.0.len() != 32 || hash(&fresh_seed.0) != text(&fresh, "unlock_hash") {
            return Err(error("SDK_RESPONSE_SIGNATURE_INVALID"));
        }
        let no_cache =
            fresh["is_trial"] == true || date(&fresh["grace_until"]) <= date(&fresh["issued_at"]);
        if no_cache {
            s.data["payload_no_cache"] = json!(true);
            self.clear_payload_keys();
        }
        let wm = PayloadSecret(payload_response_watermark(&data["watermark"])?);
        let e = decode(text(&data, "e"))?;
        let nonce = decode(text(&data, "n"))?;
        let ciphertext = decode(text(&data, "c"))?;
        if e.len() != 32 || nonce.len() != 12 || ciphertext.len() != 48 {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let peer: [u8; 32] = e
            .as_slice()
            .try_into()
            .map_err(|_| error("SDK_RESPONSE_INVALID"))?;
        let shared = PayloadSecret(
            secret
                .diffie_hellman(&PublicKey::from(peer))
                .as_bytes()
                .to_vec(),
        );
        if shared.0.iter().all(|b| *b == 0) {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let aad = p.rewrap_aad(ephemeral.as_bytes(), &decode(&challenge)?)?;
        let kek = PayloadSecret(derive(
            &shared.0,
            &Sha256::digest(&aad),
            b"authgo/payload/v1/rewrap",
            32,
        )?);
        let content = PayloadSecret(
            open(&kek.0, &nonce, &ciphertext, &aad).map_err(|_| error("SDK_RESPONSE_INVALID"))?,
        );
        if content.0.len() != 32 {
            return Err(error("SDK_RESPONSE_INVALID"));
        }
        let value = [content.0.as_slice(), wm.0.as_slice()].concat();
        self.save_payload_material(p, &fresh, disabled || no_cache, &value);
        self.save_protected(text(&data, "ticket"));
        Ok(value)
    }
}

#[cfg(test)]
mod payload_v2_tests {
    use super::*;
    fn vector() -> Value {
        parse(include_bytes!("../../vectors/payload-cache-v2.json")).unwrap()
    }
    fn payload(_version: u64) -> RawPayload {
        RawPayload::parse(canonical(&vector()["payload"]).as_bytes()).unwrap()
    }
    fn clock() -> i64 {
        vector()["proof_now"].as_i64().unwrap()
    }
    fn grant_value() -> Value {
        let v = vector();
        parse(&decode(text(&v, "ticket").split('.').next().unwrap()).unwrap()).unwrap()
    }
    fn client(root: &std::path::Path) -> Client {
        let p = payload(2);
        let options = Options {
            clock,
            cache_dir: Some(root.to_path_buf()),
            fingerprint: Some(text(&vector(), "fingerprint").to_owned()),
            ..Options::default()
        };
        Client::with_options(text(&p.document, "config"), options).unwrap()
    }
    #[test]
    fn post_signature_watermark_mutation_invalidates_signed_response_data() {
        // Same canonical signed data boundary as Client::request. Native Rust
        // protected execution uses the Go stub, covered by the real E2E suite.
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let mut envelope = json!({"code":"OK","data":{"watermark":"19".repeat(32),"request_nonce":"fixture-nonce"},"ts":123});
        let original = canonical(&envelope);
        let signature = signer.sign(original.as_bytes());
        assert!(verify(
            signer.verifying_key().as_bytes(),
            original.as_bytes(),
            &signature.to_bytes()
        ));
        envelope["data"]["watermark"] = json!("2a".repeat(32));
        assert!(payload_response_watermark(&envelope["data"]["watermark"]).is_ok());
        assert!(!verify(
            signer.verifying_key().as_bytes(),
            canonical(&envelope).as_bytes(),
            &signature.to_bytes()
        ));
        envelope["data"]["watermark"] = json!("19".repeat(32));
        assert!(verify(
            signer.verifying_key().as_bytes(),
            canonical(&envelope).as_bytes(),
            &signature.to_bytes()
        ));
    }
    #[test]
    fn payload_vectors_and_exact_schema() {
        let p = payload(2);
        let v = vector();
        assert_eq!(
            p.cache_label(text(&v, "fingerprint")),
            payload_unhex(text(&v, "label_hex")).unwrap()
        );
        let p = payload(2);
        assert!(p.aad().starts_with(b"authgo-payload-envelope-v2\0"));
        assert!(p
            .rewrap_aad(&[1; 32], &[2; 32])
            .unwrap()
            .starts_with(b"authgo-payload-rewrap-v2\0"));
        let mut old = p.to_json();
        old["v"] = json!(99);
        assert_eq!(
            parse_payload(canonical(&old).as_bytes()).unwrap_err().code,
            "PAYLOAD_INVALID"
        );
        for (key, value) in [
            ("main_class", json!("")),
            ("size", json!(0)),
            ("encoding", json!("tar")),
            ("name", json!("wrong")),
        ] {
            let mut doc = p.to_json();
            let mut manifest = parse(&p.manifest).unwrap();
            let files = manifest["files"].as_array_mut().unwrap();
            files.last_mut().unwrap()[key] = value;
            doc["manifest"] = json!(b64(canonical(&manifest).as_bytes()));
            assert!(parse_payload(canonical(&doc).as_bytes()).is_err());
        }
        let duplicate = canonical(&p.to_json()).replace("\"v\":2", "\"v\":2,\"v\":2");
        assert!(parse_payload(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn signed_watermark_is_lower_hex_nonzero_and_private_material_is_exact() {
        for value in [
            Value::Null,
            json!(32),
            json!("00".repeat(32)),
            json!("AA".repeat(32)),
            json!("19".repeat(31)),
        ] {
            assert_eq!(
                payload_response_watermark(&value).unwrap_err().code,
                "SDK_RESPONSE_INVALID"
            );
        }
        let wm = payload_response_watermark(&json!("19".repeat(32))).unwrap();
        assert_eq!(wm, vec![0x19; 32]);
        let p = payload(2);
        assert!(!p.valid_material(&[1; 32]));
        assert!(!p.valid_material(&[0; 64]));
        assert!(p.valid_material(&[1; 64]));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn cache_binding_trial_expiry_and_refusal_cleanup() {
        let root = std::env::temp_dir().join(format!("authgo-v2-{}", b64(&random(12))));
        fs::create_dir_all(&root).unwrap();
        let c = client(&root);
        let p = payload(2);
        let g = grant_value();
        let material = vec![0x19; 64];
        c.save_payload_material(&p, &g, false, &material);
        assert_eq!(c.load_payload_material(&p, &g, false).unwrap(), material);
        let m = c.payload_cache_material(&p, &g, false).unwrap();
        assert!(m
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("authgo-payload-v2-"));
        assert!(fs::read_to_string(&m.path)
            .unwrap()
            .starts_with("AUTHGO-PAYLOAD-CACHE-v2."));
        let mut other = g.clone();
        other["license_id"] = json!(43);
        assert!(c.load_payload_material(&p, &other, false).is_err());
        other = g.clone();
        other["is_trial"] = json!(true);
        assert_eq!(
            c.load_payload_material(&p, &other, false).unwrap_err().code,
            "SDK_GRACE_EXPIRED"
        );
        other = g.clone();
        other["grace_until"] = json!(chrono::DateTime::from_timestamp(clock(), 0)
            .unwrap()
            .to_rfc3339());
        assert_eq!(
            c.load_payload_material(&p, &other, false).unwrap_err().code,
            "SDK_GRACE_EXPIRED"
        );
        let nonce = random(12);
        fs::write(
            &m.path,
            format!(
                "AUTHGO-PAYLOAD-CACHE-v2.{}",
                b64(&[
                    nonce.clone(),
                    seal(&m.key.0, &nonce, &[1; 32], &m.aad).unwrap()
                ]
                .concat())
            ),
        )
        .unwrap();
        assert_eq!(
            c.load_payload_material(&p, &g, false).unwrap_err().code,
            "SDK_CACHE_INVALID"
        );
        c.clear_payload_keys();
        assert!(fs::read_dir(&root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("authgo-payload-v")));
        fs::remove_dir_all(&root).unwrap();
    }
}
