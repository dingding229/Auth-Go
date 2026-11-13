// Test image ONLY; copied into the SDK's examples in a separate build stage.
use authgo::{Guard, GuardOptions, Options, EXIT_LICENSE};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
static ADVANCE: AtomicBool = AtomicBool::new(false);
fn clock() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now + if ADVANCE.load(Ordering::Relaxed) {
        72 * 3600 + 1
    } else {
        0
    }
}
fn main() {
    let options = GuardOptions {
        config: env!("AUTHGO_CONFIG").into(),
        version: "1.0.0".into(),
        sdk_options: Options {
            clock,
            ..Default::default()
        },
        on_change: Some(Arc::new(|result, error| {
            if let Some(r) = result {
                println!("clock agent: {}", r.status);
                if r.status == "grace" {
                    ADVANCE.store(true, Ordering::Relaxed);
                }
            }
            if let Some(e) = error {
                println!("clock agent: {e}");
            }
        })),
        ..Default::default()
    };
    match Guard::start(options) {
        Ok(g) => {
            println!("clock ready");
            g.done().wait();
            if let Some(e) = g.error() {
                println!("clock stopped: {e}");
            }
            let _ = g.close();
        }
        Err(e) => println!("clock startup: {e}"),
    }
    std::process::exit(EXIT_LICENSE);
}
