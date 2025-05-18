use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use api::gog::overlay::OverlayPeerMessage;
use axum::extract::Path;
use clap::{Parser};
use env_logger::{Builder, Env, Target};
use futures_util::future::join_all;
use log::{debug, error, info};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};
use axum::{
    routing::get,
    Router,
    extract::{
        Query,
        State,
        Host,
    },
    response::Json,
    routing::get_service,
    http::{header, HeaderMap, StatusCode},
};
use tower_http::services::ServeFile;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use axum_server::tls_rustls::RustlsConfig;

#[macro_use]
extern crate lazy_static;
mod api;
mod config;
mod constants;
mod db;
mod paths;
mod proto;
mod hosts_modifier;

use crate::api::notification_pusher::PusherEvent;
use crate::api::structs::{Token, UserInfo};
use rand::{distributions::Alphanumeric, Rng};

static CERT: &[u8] = include_bytes!("../external/rootCA.pem");

#[derive(Clone)]
struct AppState {
    user_id: String,
    username: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, help = "User name")]
    username: String,

    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,
}

#[derive(Serialize, Debug)]
struct GogUser {
    id: String,
    username: String,
}

#[derive(Serialize, Debug)]
struct GogUsersResponse {
    users: Vec<GogUser>,
}

lazy_static! {
    static ref CONFIG: config::Configuration = config::load_config().unwrap_or_default();
    static ref LOCALE: String = sys_locale::get_locale()
        .and_then(|x| if !x.contains("-") { None } else { Some(x) })
        .unwrap_or_else(|| String::from("en-US"));
}

fn generate_random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn generate_random_numeric_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::from(0..10))
        .take(len)
        .map(|num| std::char::from_digit(num, 10).unwrap())
        .collect()
}

#[derive(Deserialize, Debug)]
struct TokenRequestParams {
    grant_type: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize, Debug)]
struct GogAuthTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u32,
    token_type: String,
    session_id: String, 
    user_id: String,
}


async fn handle_gog_token_request(
    Query(params): Query<TokenRequestParams>,
    State(app_state): State<AppState>, // Extract AppState
) -> Json<GogAuthTokenResponse> {

    debug!("[HTTP SERVER] Received /token request: {:?}", params);

    let client_id = params.client_id.unwrap_or_else(|| "unknown_client_id".to_string());
    let new_access_token = generate_random_string(192);
    let new_refresh_token = generate_random_string(64);
    let session_id = generate_random_numeric_string(19);
    let user_id_for_response = app_state.user_id;


    debug!("[HTTP SERVER] Responding to /token for client_id {}: new_access_token: {}, new_refresh_token: {}",
        client_id, new_access_token, new_refresh_token
    );

    Json(GogAuthTokenResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        expires_in: 3600, // e.g., 1 hour
        token_type: "Bearer".to_string(),
        session_id: session_id,
        user_id: user_id_for_response,
    })
}

async fn handle_gog_users_request(
    State(app_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Host(host): Host,
) -> Result<Json<serde_json::Value>, StatusCode> {
    debug!("[HTTP SERVER] Received /users request on host {}: {:?}, Headers: {:?}", host, params, headers);

    if !headers.contains_key(header::AUTHORIZATION) {
        error!("[HTTP SERVER] /users request missing Authorization header.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let requested_ids_str = match params.get("ids") {
        Some(ids) => ids,
        None => return Err(StatusCode::BAD_REQUEST),
    };

    let requested_ids: Vec<&str> = requested_ids_str.split(',').collect();
    let user_id_to_return = requested_ids.get(0);

    let user = serde_json::json!({
        "id": user_id_to_return,
        "username": app_state.username,
        "avatar": {
            "sdk_img_32": "https://127.0.0.1/avatar_small.jpg",
            "sdk_img_64": "https://127.0.0.1/avatar_medium.jpg",
            "sdk_img_184": "https://127.0.0.1/avatar_large.jpg"
        },
    });

    if requested_ids.len() == 1 {
        Ok(Json(user))
    } else {
        Ok(Json(json!({ "users": [user] })))
    }
}

async fn handle_gog_friends_request(
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    // Optionally check Authorization header here
    // Return an empty array or a fake list
    Json(serde_json::json!({
        "items": []
    }))
}

async fn handle_gog_presence_status(
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let user_ids = params.get("user_ids")
        .map(|ids| ids.split(',').collect::<Vec<_>>())
        .unwrap_or_default();

    let statuses: Vec<_> = user_ids.iter().map(|&id| {
        serde_json::json!({
            "user_id": id,
            "status": "offline"
        })
    }).collect();

    Json(serde_json::json!({ "statuses": statuses }))
}

async fn handle_presence_status(
    Path(user_id): Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    Json(serde_json::json!({}))
}


#[tokio::main]
async fn main() {
    let args = Args::parse();
    let log_level = if args.verbose { "debug" } else { "info" };
    let env = Env::default().filter_or("COMET_LOG", log_level);
    Builder::from_env(env)
        .target(Target::Stderr)
        .filter_module("h2::codec", log::LevelFilter::Off)
        .init();

    log::debug!("Configuration file {:?}", *CONFIG);
    log::info!("Preferred language: {}", LOCALE.as_str());

    let initial_tcp_access_token = generate_random_string(192);
    let initial_tcp_refresh_token = generate_random_string(64);
    
    let galaxy_user_id_val = generate_random_numeric_string(19);

    let certificate = reqwest::tls::Certificate::from_pem(CERT).unwrap();
    let reqwest_client = Client::builder()
        .user_agent(format!("Comet/{}", env!("CARGO_PKG_VERSION")))
        .add_root_certificate(certificate)
        .build()
        .expect("Failed to build reqwest client");

    let user_info = Arc::new(UserInfo {
        username: args.username.clone(),
        galaxy_user_id: galaxy_user_id_val.clone(),
    });
    let cloned_user_info = user_info.clone();

    let app_state = AppState {
        user_id: galaxy_user_id_val.clone(), 
        username: args.username.clone(), 
    };

    let token_store: constants::TokenStorage = Arc::new(Mutex::new(HashMap::new()));
    let galaxy_token = Token::new(initial_tcp_access_token.clone(), initial_tcp_refresh_token.clone());
    let mut store_lock = token_store.lock().await; 
    store_lock.insert(String::from(constants::GALAXY_CLIENT_ID), galaxy_token);
    drop(store_lock);
    let cloned_token_store = token_store.clone();

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let ctrl_c_shutdown_token = shutdown_token.clone();
    let http_server_shutdown_token_for_axum = shutdown_token.clone();
    let tcp_server_shutdown_token = shutdown_token.clone();
    let hosts_cleanup_shutdown_token = shutdown_token.clone();
        
    // Add hosts file
    if let Err(e) = hosts_modifier::add_redirect_entry().await {
        error!("[MAIN] Failed to add hosts file entry: {}. Ensure running as admin. HTTP redirection for auth.gog.com might not work.", e);
    }

    //Spawn the Axum HTTPS server
    tokio::spawn(async move {
        let app = Router::new()
            .route("/token", get(handle_gog_token_request))
            .route("/users", get(handle_gog_users_request))
            .route("/avatar_small.jpg", get_service(ServeFile::new("image.jpg")))
            .route("/avatar_medium.jpg", get_service(ServeFile::new("image.jpg")))
            .route("/avatar_large.jpg", get_service(ServeFile::new("image.jpg")))
            .route("/users/:user_id/friends", get(handle_gog_friends_request))
            .route("/users/:user_id/status", axum::routing::post(handle_presence_status))
            .route("/presence/status", get(handle_gog_presence_status))
            .with_state(app_state.clone());

        let addr = SocketAddr::from(([127, 0, 0, 1], 443));

        let tls_config = match RustlsConfig::from_pem_file("cert.pem", "key.pem").await {
            Ok(config) => config,
            Err(e) => {
                error!("[HTTP SERVER] Failed to load TLS certificates (cert.pem, key.pem): {}. HTTPS server will not start.", e);
                return;
            }
        };

        info!("[HTTP SERVER] TLS certificates loaded. Listening on {} (HTTPS)", addr);

        let server_future = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service());

        // Prepare the shutdown signal future
        let shutdown_signal_future = async {
            http_server_shutdown_token_for_axum.cancelled().await;
            info!("[HTTP SERVER] Graceful shutdown signal received for HTTP server.");
        };

        // Run the server with graceful shutdown
        tokio::select! {
            biased;
            server_result = server_future => {
                match server_result {
                    Ok(_) => info!("[HTTP SERVER] Server completed successfully."),
                    Err(e) => error!("[HTTP SERVER] Server error: {}", e),
                }
            }
            _ = shutdown_signal_future => {
                info!("[HTTP SERVER] HTTP server is shutting down due to signal.");
            }
        }
        info!("[HTTP SERVER] HTTP server task finished.");
    });
    // Spawn the TCP server
    let listener = TcpListener::bind("127.0.0.1:9977")
        .await
        .expect("Failed to bind to port 9977 for TCP service");
    info!("[TCP SERVER] Listening on 127.0.0.1:9977");

    let (overlay_event_sender_main, _) = broadcast::channel::<(u32, OverlayPeerMessage)>(16);
    let (topic_sender, _) = tokio::sync::broadcast::channel::<PusherEvent>(20);
    let (client_exit, mut con_exit_recv) = tokio::sync::mpsc::channel::<()>(10);

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen to ctrl c signal");
        log::warn!("Ctrl+C received. Initiating shutdown..."); // Changed to warn
        ctrl_c_shutdown_token.cancel();
    });
    tokio::spawn(async move {
        hosts_cleanup_shutdown_token.cancelled().await;
        info!("[MAIN] Shutdown signal received, attempting to clean up hosts file.");
        if let Err(e) = hosts_modifier::remove_redirect_entry().await {
            error!("[MAIN] Failed to clean up hosts file: {}", e);
        }
    });



    let comet_idle_wait: u64 = match std::env::var("COMET_IDLE_WAIT") {
        Ok(wait) => wait.parse().unwrap_or(15),
        Err(_) => 15,
    };
    let mut ever_connected = false;
    let mut active_clients = 0;
    let mut handlers = Vec::new();
    let socket_shutdown_for_loop = tcp_server_shutdown_token.clone();

    loop {
        tokio::select! {
            biased; // Prioritize shutdown signal
            _ = socket_shutdown_for_loop.cancelled() => {
                info!("[TCP SERVER] Shutdown signal received, stopping accept loop.");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((socket, _addr)) => {
                        info!("[TCP SERVER] New connection from {}", _addr);
                        active_clients += 1;
                        if !ever_connected { 
                            ever_connected = true;
                        }
                        let mut topic_receiver = topic_sender.subscribe(); 
                        let handler_reqwest_client = reqwest_client.clone();
                        let handler_token_store = cloned_token_store.clone(); 
                        let handler_shutdown = socket_shutdown_for_loop.clone();
                        let handler_user_info = cloned_user_info.clone(); // This Arc<UserInfo> contains the galaxy_user_id
                        let handler_overlay_event_sender = overlay_event_sender_main.clone();

                        handlers.push(tokio::spawn(async move {
                            api::handlers::entry_point(
                                socket, // mut socket: TcpStream
                                handler_reqwest_client, // reqwest_client: Client
                                handler_token_store, // token_store: TokenStorage
                                handler_user_info, // user_info: Arc<UserInfo>
                                topic_receiver, // mut topic_receiver: Receiver<PusherEvent>
                                handler_overlay_event_sender, // overlay_event_sender: Sender<(u32, OverlayPeerMessage)>
                                handler_shutdown // shutdown_token: CancellationToken
                            )
                            .await;
                        }));
                    }
                    Err(error) => {
                        error!("[TCP SERVER] Failed to accept the connection {:?}", error);
                        // Potentially break or sleep if accept fails too many times
                    }
                }
            }
            Some(_) = con_exit_recv.recv() => {
                active_clients -= 1;
                info!("[TCP SERVER] Client disconnected. Active clients: {}", active_clients);
            }
            _ = tokio::time::sleep(Duration::from_secs(comet_idle_wait)), if active_clients == 0 && ever_connected => {
                info!("[TCP SERVER] Idle timeout reached with no active clients. Shutting down.");
                tcp_server_shutdown_token.cancel();
                break;
            }
        }
    }
    info!("[MAIN] Waiting for all client handlers to complete...");
    join_all(handlers).await;

    if shutdown_token.is_cancelled() {
        info!("[MAIN] Shutdown process was initiated. Allowing cleanup tasks to run.");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    info!("CometOffline shutting down completely.");
}
