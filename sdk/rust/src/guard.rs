//! Application-owned signals; only a standard-library background thread.
use crate::{date, error, number, Client, Error, Options, ResultData};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const EXIT_LICENSE: i32 = 77;
pub type OnChange = Arc<dyn Fn(Option<ResultData>, Option<Error>) + Send + Sync>;

#[derive(Default)]
pub struct GuardOptions {
    pub config: String,
    pub license: String,
    pub version: String,
    pub on_change: Option<OnChange>,
    pub sdk_options: Options,
}

// Private seam for deterministic lifecycle tests; production always uses Client.
trait Backend: Send + Sync {
    fn now(&self) -> i64;
    fn verify(&self) -> Result<ResultData, Error>;
    fn heartbeat(&self) -> Result<ResultData, Error>;
    fn validate(&self, ticket: &str) -> Result<(), Error>;
    fn release(&self) -> Result<(), Error>;
}
impl Backend for Client {
    fn now(&self) -> i64 {
        (self.options.clock)()
    }
    fn verify(&self) -> Result<ResultData, Error> {
        self.verify()
    }
    fn heartbeat(&self) -> Result<ResultData, Error> {
        self.heartbeat()
    }
    fn validate(&self, ticket: &str) -> Result<(), Error> {
        self.validate(ticket)
    }
    fn release(&self) -> Result<(), Error> {
        self.release_seat()
    }
}
struct Status {
    result: ResultData,
    error: Option<Error>,
    stop: bool,
    stopped: bool,
    closing: Option<Instant>,
    close_result: Option<Result<(), Error>>,
}
struct Shared {
    state: Mutex<Status>,
    changed: Condvar,
}
impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, Status> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}
#[derive(Clone)]
pub struct Completion {
    shared: Arc<Shared>,
}
impl Completion {
    pub fn is_done(&self) -> bool {
        self.shared.state().error.is_some()
    }
    pub fn wait(&self) {
        let mut state = self.shared.state();
        while state.error.is_none() {
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
    }
}
pub struct Guard {
    client: Arc<dyn Backend>,
    shared: Arc<Shared>,
}
impl Guard {
    pub fn start(mut options: GuardOptions) -> Result<Self, Error> {
        crate::watermark::touch();
        crate::protected::harden();
        if options.config.is_empty() {
            return Err(error("SDK_INVALID_CONFIG"));
        }
        options.sdk_options.version = options.version;
        let client = Arc::new(Client::with_options(&options.config, options.sdk_options)?);
        let license = if options.license.is_empty() {
            std::env::var("AUTHGO_LICENSE").unwrap_or_default()
        } else {
            options.license
        };
        let result = client.guard_check(&license)?;
        Self::launch(client, result, options.on_change)
    }
    fn launch(
        client: Arc<dyn Backend>,
        result: ResultData,
        on_change: Option<OnChange>,
    ) -> Result<Self, Error> {
        let shared = Arc::new(Shared {
            state: Mutex::new(Status {
                result,
                error: None,
                stop: false,
                stopped: false,
                closing: None,
                close_result: None,
            }),
            changed: Condvar::new(),
        });
        let worker = shared.clone();
        let backend = client.clone();
        thread::Builder::new()
            .name("authgo-guard".into())
            .spawn(move || {
                let outcome = run(backend.as_ref(), &worker, on_change.as_ref());
                let mut state = worker.state();
                if !state.stop {
                    if let Err(e) = outcome {
                        state.error = Some(e);
                    }
                }
                state.stopped = true;
                worker.changed.notify_all();
            })
            .map_err(|_| error("SDK_NETWORK_ERROR"))?;
        Ok(Self { client, shared })
    }
    pub fn result(&self) -> ResultData {
        self.shared.state().result.clone()
    }
    pub fn done(&self) -> Completion {
        Completion {
            shared: self.shared.clone(),
        }
    }
    pub fn is_done(&self) -> bool {
        self.done().is_done()
    }
    pub fn error(&self) -> Option<Error> {
        self.shared.state().error.clone()
    }
    pub fn require(&self, feature: &str) -> Result<(), Error> {
        let active = |state: &Status| -> Result<(), Error> {
            if let Some(e) = &state.error {
                return Err(e.clone());
            }
            if state.stop {
                return Err(error("SDK_NOT_ACTIVATED"));
            }
            Ok(())
        };
        let result = {
            let state = self.shared.state();
            active(&state)?;
            state.result.clone()
        };
        // Client::validate can wait behind a network operation's state lock.
        // Keep our lifecycle mutex free so close remains bounded.
        self.client.validate(result.ticket())?;
        let state = self.shared.state();
        active(&state)?;
        if !feature.is_empty() && result.data["features"][feature] != true {
            return Err(error("INVALID_POLICY"));
        }
        Ok(())
    }
    pub fn close(&self) -> Result<(), Error> {
        let mut state = self.shared.state();
        if state.closing.is_none() {
            state.stop = true;
            state.closing = Some(Instant::now());
            self.shared.changed.notify_all();
            let shared = self.shared.clone();
            let client = self.client.clone();
            if thread::Builder::new()
                .name("authgo-release".into())
                .spawn(move || {
                    let mut state = shared.state();
                    while !state.stopped && state.close_result.is_none() {
                        let remaining = Duration::from_secs(5)
                            .saturating_sub(state.closing.map(|t| t.elapsed()).unwrap_or_default());
                        if remaining.is_zero() {
                            break;
                        }
                        state = shared
                            .changed
                            .wait_timeout(state, remaining)
                            .unwrap_or_else(|p| p.into_inner())
                            .0;
                    }
                    if state.close_result.is_some() {
                        return;
                    }
                    let ready = state.stopped
                        && state
                            .closing
                            .map(|t| t.elapsed() < Duration::from_secs(5))
                            .unwrap_or(false);
                    drop(state);
                    let result = if ready {
                        client.release()
                    } else {
                        Err(error("SDK_NETWORK_ERROR"))
                    };
                    let mut state = shared.state();
                    if state.close_result.is_none() {
                        state.close_result = Some(result);
                    }
                    shared.changed.notify_all();
                })
                .is_err()
            {
                state.close_result = Some(Err(error("SDK_NETWORK_ERROR")));
            }
        }
        while state.close_result.is_none() {
            let remaining = Duration::from_secs(5)
                .saturating_sub(state.closing.map(|t| t.elapsed()).unwrap_or_default());
            if remaining.is_zero() {
                state.close_result = Some(Err(error("SDK_NETWORK_ERROR")));
                self.shared.changed.notify_all();
                break;
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        state
            .close_result
            .clone()
            .unwrap_or_else(|| Err(error("SDK_NETWORK_ERROR")))
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn notify(
    shared: &Shared,
    result: Option<&ResultData>,
    failure: Option<&Error>,
    change: Option<&OnChange>,
) {
    {
        let mut state = shared.state();
        if state.stop {
            return;
        }
        if let Some(r) = result {
            state.result = r.clone();
        }
        if let Some(e) = failure {
            state.error = Some(e.clone());
            shared.changed.notify_all();
        }
    }
    if let Some(change) = change {
        change(result.cloned(), failure.cloned());
    }
}
fn checked(
    client: &dyn Backend,
    heartbeat: bool,
    shared: &Shared,
    change: Option<&OnChange>,
) -> Result<ResultData, Error> {
    let value = if heartbeat {
        client.heartbeat()
    } else {
        client.verify()
    };
    match &value {
        Ok(r) => notify(shared, Some(r), None, change),
        Err(e) => notify(shared, None, Some(e), change),
    }
    value
}
fn run(client: &dyn Backend, shared: &Shared, change: Option<&OnChange>) -> Result<(), Error> {
    if shared.state().stop {
        return Ok(());
    }
    let mut result = checked(client, false, shared, change)?;
    let mut verify_at = client
        .now()
        .saturating_add(number(&result.data, "next_check_in"));
    let mut heartbeat_at = client.now().saturating_add(result.heartbeat_interval);
    loop {
        let floating = result.data["floating"] == true;
        let next = verify_at
            .min(if floating { heartbeat_at } else { i64::MAX })
            .min(date(&result.data["expires_at"]))
            .min(if result.status == "grace" {
                result.end
            } else {
                date(&result.data["lease_expires_at"])
            });
        let state = shared.state();
        if state.stop {
            return Ok(());
        }
        let delay = Duration::from_secs(next.saturating_sub(client.now()).max(0) as u64);
        let (state, _) = shared
            .changed
            .wait_timeout_while(state, delay, |s| !s.stop)
            .unwrap_or_else(|p| p.into_inner());
        if state.stop {
            return Ok(());
        }
        drop(state);
        if client.now() >= verify_at
            || (client.now() >= next && (!floating || client.now() < heartbeat_at))
        {
            result = checked(client, false, shared, change)?;
            verify_at = client
                .now()
                .saturating_add(number(&result.data, "next_check_in"));
        }
        if result.data["floating"] == true && client.now() >= heartbeat_at && !shared.state().stop {
            result = checked(client, true, shared, change)?;
            heartbeat_at = client.now().saturating_add(result.heartbeat_interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Fake {
        failure: AtomicBool,
        calls: AtomicUsize,
        releases: AtomicUsize,
        block: AtomicBool,
        release_failure: AtomicBool,
        validate_block: AtomicBool,
        validating: AtomicBool,
        long_verify: AtomicBool,
        heartbeats: AtomicUsize,
    }
    fn result(status: &str) -> ResultData {
        ResultData {
            is_trial: false,
            maintenance_until: None,
            latest_entitled_version: String::new(),
            data: json!({"next_check_in":1,"floating":true,"features":{"export":true,"nested":{"x":1}}}),
            status: status.into(),
            offline: status != "online",
            reason: String::new(),
            remaining_seconds: 30,
            heartbeat_interval: 1,
            cache_warning: None,
            ticket: "proof".into(),
            end: crate::now() + 30,
        }
    }
    impl Backend for Fake {
        fn now(&self) -> i64 {
            crate::now()
        }
        fn verify(&self) -> Result<ResultData, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            while self.block.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            if self.failure.load(Ordering::SeqCst) {
                Err(error("SDK_GRACE_EXPIRED"))
            } else {
                let mut result = result("grace");
                if self.long_verify.load(Ordering::SeqCst) {
                    result.data["next_check_in"] = json!(10);
                }
                Ok(result)
            }
        }
        fn heartbeat(&self) -> Result<ResultData, Error> {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
            self.verify()
        }
        fn validate(&self, ticket: &str) -> Result<(), Error> {
            self.validating.store(true, Ordering::SeqCst);
            while self.validate_block.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(ticket, "proof");
            Ok(())
        }
        fn release(&self) -> Result<(), Error> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            if self.release_failure.load(Ordering::SeqCst) {
                Err(error("SDK_NETWORK_ERROR"))
            } else {
                Ok(())
            }
        }
    }
    fn fake() -> Arc<Fake> {
        Arc::new(Fake {
            failure: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            block: AtomicBool::new(false),
            release_failure: AtomicBool::new(false),
            validate_block: AtomicBool::new(false),
            validating: AtomicBool::new(false),
            long_verify: AtomicBool::new(false),
            heartbeats: AtomicUsize::new(0),
        })
    }
    fn wait_for(test: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(3);
        while !test() {
            assert!(Instant::now() < end, "guard did not progress");
            thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn missing_config_fails_without_thread() {
        assert_eq!(
            Guard::start(GuardOptions::default())
                .err()
                .expect("missing config")
                .code(),
            "SDK_INVALID_CONFIG"
        );
        assert_eq!(EXIT_LICENSE, 77);
    }
    #[test]
    fn first_check_failure_never_notifies() {
        use base64::Engine;
        let v: Value =
            serde_json::from_slice(include_bytes!("../../vectors/v2.json")).expect("vector");
        let public =
            crate::decode(v["ed25519_public"].as_str().expect("public")).expect("public bytes");
        let config = format!(
            "authgo2.{}",
            crate::b64(
                json!({
                    "url":"http://127.0.0.1:1", "app_key":"test", "app_secret":"secret",
                    "public_key":base64::engine::general_purpose::STANDARD.encode(public),
                    "gateway_key":v["gateway_public"]
                })
                .to_string()
                .as_bytes()
            )
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let result = Guard::start(GuardOptions {
            config,
            license: "abc".into(),
            sdk_options: Options {
                fingerprint: Some("a".repeat(64)),
                cache_dir: Some(std::path::PathBuf::new()),
                ..Default::default()
            },
            on_change: Some(Arc::new(move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });
        assert_eq!(
            result.err().expect("invalid key").code(),
            "INVALID_LICENSE_KEY"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn heartbeat_uses_response_metadata_not_grant_fields() {
        let f = fake();
        f.long_verify.store(true, Ordering::SeqCst);
        let g = Guard::launch(f.clone(), result("online"), None).expect("launch");
        assert!(g.result().data["heartbeat_interval"].is_null());
        assert_eq!(g.result().heartbeat_interval, 1);
        wait_for(|| f.heartbeats.load(Ordering::SeqCst) > 0);
        assert!(f.calls.load(Ordering::SeqCst) <= 3);
        g.close().expect("close");
    }
    #[test]
    fn close_is_not_blocked_by_a_require_reader() {
        let f = fake();
        f.validate_block.store(true, Ordering::SeqCst);
        let g = Arc::new(Guard::launch(f.clone(), result("online"), None).expect("launch"));
        let reader = g.clone();
        let pending = thread::spawn(move || reader.require(""));
        wait_for(|| f.validating.load(Ordering::SeqCst));
        let failsafe = f.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));
            failsafe.validate_block.store(false, Ordering::SeqCst);
        });
        let start = Instant::now();
        let closed = g.close();
        f.validate_block.store(false, Ordering::SeqCst);
        closed.expect("release");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(
            pending.join().expect("reader").expect_err("closed").code(),
            "SDK_NOT_ACTIVATED"
        );
    }
    #[test]
    fn release_error_does_not_complete_guard() {
        let f = fake();
        f.release_failure.store(true, Ordering::SeqCst);
        let g = Guard::launch(f, result("online"), None).expect("launch");
        assert_eq!(g.close().expect_err("release").code(), "SDK_NETWORK_ERROR");
        assert!(!g.is_done());
        assert!(g.error().is_none());
    }
    #[test]
    fn concurrent_copies_local_require_close_and_completion() {
        let f = fake();
        let changes = Arc::new(AtomicUsize::new(0));
        let seen = changes.clone();
        let g = Arc::new(
            Guard::launch(
                f.clone(),
                result("online"),
                Some(Arc::new(move |_, _| {
                    seen.fetch_add(1, Ordering::SeqCst);
                })),
            )
            .expect("launch"),
        );
        wait_for(|| changes.load(Ordering::SeqCst) > 0);
        assert_eq!(g.result().status, "grace");
        assert!(!g.is_done());
        let threads: Vec<_> = (0..12)
            .map(|_| {
                let g = g.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        let mut r = g.result();
                        r.data["features"]["nested"]["x"] = json!(99);
                        g.require("export").expect("local");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("reader");
        }
        assert_eq!(g.result().data["features"]["nested"]["x"], 1);
        assert_eq!(
            g.require("missing").expect_err("feature").code(),
            "INVALID_POLICY"
        );
        let calls = f.calls.load(Ordering::SeqCst);
        g.require("").expect("local");
        assert_eq!(f.calls.load(Ordering::SeqCst), calls);
        f.failure.store(true, Ordering::SeqCst);
        wait_for(|| g.is_done());
        g.done().wait();
        assert_eq!(
            g.error().expect("final failure").code(),
            "SDK_GRACE_EXPIRED"
        );
        assert_eq!(g.require("").expect_err("done").code(), "SDK_GRACE_EXPIRED");
        g.close().expect("close");
        g.close().expect("idempotent");
        assert_eq!(f.releases.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn grace_does_not_complete_and_close_is_bounded() {
        let f = fake();
        f.block.store(true, Ordering::SeqCst);
        let g = Guard::launch(f.clone(), result("grace"), None).expect("launch");
        wait_for(|| f.calls.load(Ordering::SeqCst) > 0);
        assert!(!g.is_done());
        assert_eq!(g.result().status, "grace");
        let start = Instant::now();
        let closed = g.close();
        f.block.store(false, Ordering::SeqCst);
        assert_eq!(closed.expect_err("bounded").code(), "SDK_NETWORK_ERROR");
        assert!(start.elapsed() < Duration::from_millis(5300));
        thread::sleep(Duration::from_millis(30));
        assert_eq!(f.releases.load(Ordering::SeqCst), 0);
        assert_eq!(
            g.require("").expect_err("closed").code(),
            "SDK_NOT_ACTIVATED"
        );
    }
}
