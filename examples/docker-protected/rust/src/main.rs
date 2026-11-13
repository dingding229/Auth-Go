use authgo::{Guard, GuardOptions, EXIT_LICENSE};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}
// Linux container example only. Rust std has no POSIX signal API; the SDK has
// no signal handler. This application handler only stores a lock-free bit.
extern "C" {
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
}
fn main() {
    std::process::exit(run());
}
fn run() -> i32 {
    // SAFETY: Linux SIGINT/SIGTERM; static C-ABI handler lives for the process.
    unsafe {
        signal(2, stop);
        signal(15, stop);
    }
    let options = GuardOptions {
        config: env!("AUTHGO_CONFIG").into(),
        version: env!("VERSION").into(),
        on_change: Some(Arc::new(|r, e| {
            if let Some(e) = e {
                eprintln!("授权检查: {e}");
            }
            if let Some(r) = r {
                println!("授权状态: {}", r.status);
                if let Some(w) = r.cache_warning {
                    println!("缓存提示: {w}");
                }
            }
        })),
        ..Default::default()
    };
    // Keep the application's signal loop responsive during synchronous startup.
    let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
    if let Err(e) = std::thread::Builder::new()
        .name("business-start".into())
        .spawn(move || {
            let _ = ready_tx.send(Guard::start(options));
        })
    {
        eprintln!("启动授权验证失败: {e}");
        return 1;
    }
    let guard = loop {
        if STOP.load(Ordering::Relaxed) {
            return 0;
        }
        match ready.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(g)) => break Arc::new(g),
            Ok(Err(e)) => {
                if STOP.load(Ordering::Relaxed) {
                    return 0;
                }
                eprintln!("授权验证失败: {e}");
                return EXIT_LICENSE;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("启动授权验证失败: 工作线程已停止");
                return 1;
            }
        }
    };
    if guard.result().is_trial {
        println!("当前为试用");
    }
    if let Some(w) = guard.result().cache_warning {
        println!("缓存提示: {w}");
    }
    let args: Vec<_> = std::env::args().collect();
    let addr = args
        .iter()
        .position(|a| a == "-listen")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .unwrap_or("0.0.0.0:8080");
    let result = (|| -> std::io::Result<i32> {
        let server = TcpListener::bind(addr)?;
        server.set_nonblocking(true)?;
        println!("HTTP已启动 version={}", env!("VERSION"));
        while !STOP.load(Ordering::Relaxed) && !guard.is_done() {
            match server.accept() {
                Ok((stream, _)) => {
                    let request_guard = guard.clone();
                    // A business request waiting for validation must not block
                    // the main signal/shutdown loop.
                    std::thread::Builder::new()
                        .name("business-http".into())
                        .spawn(move || {
                            let _ = respond(stream, request_guard);
                        })?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(e),
            }
        }
        if let Some(e) = guard.error() {
            eprintln!("授权已失效: {e}");
            return Ok(EXIT_LICENSE);
        }
        Ok(0)
    })();
    if let Err(e) = guard.close() {
        eprintln!("释放席位: {e}");
    }
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("HTTP服务失败: {e}");
            1
        }
    }
}

fn respond(mut stream: TcpStream, guard: Arc<Guard>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_millis(200)))?;
    let mut input = [0u8; 1024];
    let _ = stream.read(&mut input);
    let response = match guard.require("") {
        Ok(()) => {
            let padding = std::hint::black_box(include_bytes!("../padding.bin"));
            let body = format!("{{\"marker\":\"AUTHGO_payload_PROTECTED_CORE\",\"language\":\"rust\",\"unique\":\"AUTHGO_payload_RUST_CORE\",\"padding_bytes\":{},\"features\":{}}}", padding.len(), guard.result().data["features"]);
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body)
        }
        Err(error) => {
            eprintln!("授权请求: {}", error.code);
            format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                error.code.len(),
                error.code
            )
        }
    };
    stream.write_all(response.as_bytes())
}
