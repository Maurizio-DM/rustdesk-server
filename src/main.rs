// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use base64::prelude::{Engine as _, BASE64_STANDARD};
use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT,config::API_PORT, log, rand::{self, RngCore}, ResultType};
use hbbs::{common::*, *};
use rocket::{
    config::LogLevel,
    data::{Limits, ToByteUnit},
    fairing::{Fairing, Info, Kind},
    http::{ContentType, Status},
    Request, Response,
};

use std::thread;
use sctgdesk_api_server::build_rocket;

const RMEM: usize = 0;

// The RustDesk client (Flutter) crashes with "Null check operator used on a null
// value" when an auth failure on /api/login returns an empty body: it reads the
// `error` field of what it assumes is a JSON object, and the body is empty.
// This response fairing rewrites empty-bodied login 401s into a parseable JSON
// error so the client shows a clean "wrong password" message instead of crashing.
struct LoginErrorJson;

#[rocket::async_trait]
impl Fairing for LoginErrorJson {
    fn info(&self) -> Info {
        Info {
            name: "JSON error body for /api/login auth failures",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        if res.status() == Status::Unauthorized && req.uri().path().as_str().ends_with("/login") {
            let body = r#"{"error":"Wrong username or password."}"#;
            res.set_status(Status::Unauthorized);
            res.set_header(ContentType::JSON);
            res.set_sized_body(body.len(), std::io::Cursor::new(body));
        }
    }
}

// Resolves the Rocket `secret_key` used to sign private cookies/sessions.
// Previously this was a single key hardcoded in the source
// ("wJq+s/xvwZjmMX3ev0p4gQTs9Ej5wt0brsk3ZGhoBTg="), identical on every
// deployment built from this repo, which defeats the purpose of a secret.
// Resolution order:
//   1. `ROCKET_SECRET_KEY` environment variable, if set.
//   2. `secret_key.txt` next to the executable, if it already exists.
//   3. otherwise generate a fresh 256-bit key and persist it to
//      `secret_key.txt` so it survives restarts.
fn get_or_create_secret_key() -> String {
    if let Ok(key) = std::env::var("ROCKET_SECRET_KEY") {
        if !key.is_empty() {
            return key;
        }
    }
    let path = "secret_key.txt";
    if let Ok(key) = std::fs::read_to_string(path) {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return key;
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = BASE64_STANDARD.encode(bytes);
    if let Err(e) = std::fs::write(path, &key) {
        log::error!("failed to persist secret_key.txt: {:?}", e);
    }
    key
}

fn get_rocket_log_level() -> LogLevel {
    let log_level_env = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    match log_level_env.as_str() {
        "off" => return LogLevel::Off,
        "error" => return LogLevel::Critical,
        "warn" => return LogLevel::Normal,
        "info" => return LogLevel::Normal,
        "debug" => return LogLevel::Debug,
        "trace" => return LogLevel::Debug,
        _ => return LogLevel::Off

    }
}
#[rocket::main]
async fn start_rocket() -> ResultType<()> {
    let port = get_arg_or("api-port", API_PORT.to_string()).parse::<i32>()?;
    let figment = rocket::Config::figment()
        .merge(("address", "0.0.0.0"))
        .merge(("port", port))
        .merge(("log_level", get_rocket_log_level()))
        .merge(("secret_key", get_or_create_secret_key()))
        .merge(("ident",  format!("SCTGDeskServer/{}", env!("CARGO_PKG_VERSION"))))
        .merge(("limits", Limits::new().limit("json", 2.mebibytes())));
    let _rocket = build_rocket(figment)
        .await
        .attach(LoginErrorJson)
        .ignite()
        .await?
        .launch()
        .await;
    Ok(())
}

fn log_format(
    write: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let file = record.file().unwrap_or("unknown");
    let line = record.line().unwrap_or(0);
    let file = file.rsplitn(2, '/').next().unwrap_or(file); // Obtenez seulement le nom du fichier, pas le chemin complet
    let timestamp = now.now().to_string();
    write!(
        write,
        "{} [{}] {}:{} - {}",
        timestamp,
        record.level(),
        file,
        line,
        record.args()
    )
}

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(log_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -a, --api-port=[NUMBER(default={API_PORT})] 'Sets the listening port of API server'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] 'Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] 'Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] 'Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] 'Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'
        , --logged-in-only 'Only allow logged in user to control'",
    );
    init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let rmem = get_arg("rmem").parse::<usize>().unwrap_or(RMEM);
    let serial: i32 = get_arg("serial").parse().unwrap_or(0);

    std::env::set_var("MAIN_PKG_VERSION", env!("CARGO_PKG_VERSION"));
    let handle = thread::spawn(|| {
        let rt = rocket::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let _ = sctgdesk_api_server::ApiState::new_with_db("db_v2.sqlite3").await;
        });
    });
    handle.join().unwrap();
    let rocket_thread = thread::spawn(|| {
        let _ = start_rocket();
    });

    RendezvousServer::start(port, serial, &get_arg_or("key", "-".to_owned()), rmem)?;
    let _ = rocket_thread.join();
    Ok(())
}
