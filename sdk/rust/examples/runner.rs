use authgo::{Client, Options, ResultData};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::atomic::{AtomicI64, Ordering},
};
static CLOCK: AtomicI64 = AtomicI64::new(0);
fn clock() -> i64 {
    CLOCK.load(Ordering::Relaxed)
}
fn main() {
    let mut client: Option<Client> = None;
    let mut result: Option<ResultData> = None;
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let output = (|| -> Result<Value, authgo::Error> {
            let p: Value = serde_json::from_str(&line).map_err(|_| authgo::Error {
                code: "RUNNER_ERROR".into(),
                authenticated: false,
                cause: None,
                latest_version: String::new(),
                latest_entitled_version: String::new(),
            })?;
            let s = |k: &str| p[k].as_str().unwrap_or("");
            let mut out = json!({"code":"OK"});
            if s("op") == "init" {
                CLOCK.store(p["time"].as_i64().unwrap_or(0), Ordering::Relaxed);
                client = Some(Client::with_options(
                    s("config"),
                    Options {
                        root_cert_der: None,
                        fingerprint: if p["automatic"] == true {
                            None
                        } else {
                            Some(p["fingerprint"].as_str().unwrap_or(&"a".repeat(64)).into())
                        },
                        cache_dir: Some(PathBuf::from(
                            p["cache_dir"].as_str().unwrap_or("/tmp/authgo-rust-cache"),
                        )),
                        version: if p["unversioned"] == true {
                            ""
                        } else {
                            p["version"].as_str().unwrap_or("1.0.0")
                        }
                        .into(),
                        clock,
                    },
                )?);
                out["status"] = json!("ready");
                return Ok(out);
            }
            if s("op") == "clock" {
                CLOCK.fetch_add(p["seconds"].as_i64().unwrap_or(0), Ordering::Relaxed);
                return Ok(out);
            }
            let c = client.as_ref().ok_or_else(|| authgo::Error {
                code: "RUNNER_ERROR".into(),
                authenticated: false,
                cause: None,
                latest_version: String::new(),
                latest_entitled_version: String::new(),
            })?;
            match s("op") {
                "check" | "activate" | "verify" | "heartbeat" | "guard_check" => {
                    let r = match s("op") {
                        "check" => c.check(s("key"))?,
                        "guard_check" => c.guard_check(s("key"))?,
                        "activate" => c.activate(s("key"))?,
                        "verify" => c.verify()?,
                        _ => c.heartbeat()?,
                    };
                    out["status"] = json!(r.status);
                    result = Some(r)
                }
                "trial_info" => {
                    out["is_trial"] = json!(result.as_ref().is_some_and(|r| r.is_trial));
                }
                "release_seat" => {
                    c.release_seat()?;
                }
                "entitlement" => {
                    let r = result.as_ref().ok_or_else(|| authgo::Error {
                        code: "RUNNER_ERROR".into(),
                        authenticated: false,
                        cause: None,
                        latest_version: String::new(),
                        latest_entitled_version: String::new(),
                    })?;
                    out["maintenance_until"] = json!(r.maintenance_until);
                    out["latest_entitled_version"] = json!(r.latest_entitled_version);
                }
                "validate" => {
                    c.validate(
                        result
                            .as_ref()
                            .ok_or_else(|| authgo::Error {
                                code: "RUNNER_ERROR".into(),
                                authenticated: false,
                                cause: None,
                                latest_version: String::new(),
                                latest_entitled_version: String::new(),
                            })?
                            .ticket(),
                    )?;
                }
                "identity" => {
                    out["fingerprint"] = json!(c.identity());
                }
                "cache_warning" => {
                    out["cache_warning"] =
                        json!(result.as_ref().is_some_and(|r| r.cache_warning.is_some()));
                }
                "deactivate" => c.deactivate()?,
                "announcements" => {
                    out["count"] = json!(c.announcements()?.as_array().map_or(0, |v| v.len()))
                }
                "check_update" => {
                    let update = c.check_update(p["version"].as_str().unwrap_or("1.0.0"))?;
                    out["available"] = update["available"].clone();
                    out["version"] = update["version"].clone();
                    out["docker_image"] = update["docker_image"].clone();
                    out["docker_pull"] = update["docker_pull"].clone()
                }
                _ => {}
            }
            Ok(out)
        })();
        let out = match output {
            Ok(v) => v,
            Err(e) => {
                if e.code == "MAINTENANCE_EXPIRED" {
                    json!({"code":e.code,"latest_entitled_version":e.latest_entitled_version})
                } else if e.latest_version.is_empty() {
                    json!({"code":e.code})
                } else {
                    json!({"code":e.code,"latest_version":e.latest_version})
                }
            }
        };
        println!("{out}");
        let _ = std::io::stdout().flush();
    }
}
