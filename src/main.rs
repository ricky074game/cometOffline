use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use api::gog::overlay::OverlayPeerMessage;
use clap::{Parser};
use env_logger::{Builder, Env, Target};
use futures_util::future::join_all;
use log::{error, info};
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex};
use axum::{
    routing::get,
    Router,
    extract::Query,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

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



#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, help = "User name")]
    username: String,

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
    // Add other params GOG might send, like client_secret, scope, etc. if needed
}

#[derive(Serialize, Debug)]
struct GogAuthTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u32,
    token_type: String,
    session_id: String, // GOG often includes this
    user_id: String,    // GOG often includes this
}


async fn handle_gog_token_request(Query(params): Query<TokenRequestParams>) -> Json<GogAuthTokenResponse> {
    info!("[HTTP SERVER] Received /token request: {:?}", params);

    let client_id = params.client_id.unwrap_or_else(|| "unknown_client_id".to_string());
    let new_access_token = generate_random_string(64);
    let new_refresh_token = generate_random_string(64); 
    let session_id = generate_random_string(32);
    let user_id_for_response = generate_random_numeric_string(16);


    info!("[HTTP SERVER] Responding to /token for client_id {}: new_access_token: {}, new_refresh_token: {}",
        client_id, new_access_token, new_refresh_token
    );

    Json(GogAuthTokenResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        expires_in: 3600, // e.g., 1 hour
        token_type: "Bearer".to_string(),
        session_id,
        user_id: user_id_for_response,
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let env = Env::new().filter_or("COMET_LOG", "info");
    Builder::from_env(env)
        .target(Target::Stderr)
        .filter_module("h2::codec", log::LevelFilter::Off)
        .init();

    log::debug!("Configuration file {:?}", *CONFIG);
    log::info!("Preferred language: {}", LOCALE.as_str());

    let access_token = generate_random_string(32);
    let refresh_token = generate_random_string(32); 
    let galaxy_user_id = generate_random_numeric_string(16); 

    let certificate = reqwest::tls::Certificate::from_pem(CERT).unwrap();
    let reqwest_client = Client::builder()
        .user_agent(format!("Comet/{}", env!("CARGO_PKG_VERSION")))
        .add_root_certificate(certificate)
        .build()
        .expect("Failed to build reqwest client");

    let user_info = Arc::new(UserInfo {
        username: args.username.clone(),
        galaxy_user_id: galaxy_user_id.clone(),
    });
    let cloned_user_info = user_info.clone();

    let token_store: constants::TokenStorage = Arc::new(Mutex::new(HashMap::new()));
    let galaxy_token = Token::new(access_token.clone(), refresh_token.clone());
    let mut store_lock: tokio::sync::MutexGuard<'_, HashMap<String, Token>> = token_store.lock().await;
    store_lock.insert(String::from(constants::GALAXY_CLIENT_ID), galaxy_token);
    drop(store_lock);
    let cloned_token_store = token_store.clone();


    let listener = TcpListener::bind("127.0.0.1:9977")
        .await
        .expect("Failed to bind to port 9977");

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let ctrl_c_shutdown_token = shutdown_token.clone();
    let http_server_shutdown_token = shutdown_token.clone();
    let tcp_server_shutdown_token = shutdown_token.clone();
    let hosts_cleanup_shutdown_token = shutdown_token.clone();

    let http_server_shutdown_token = shutdown_token.clone(); // Use the same global shutdown
    // Add hosts file
    if let Err(e) = hosts_modifier::add_redirect_entry().await {
        error!("[MAIN] Failed to add hosts file entry: {}. Ensure running as admin. HTTP redirection for auth.gog.com might not work.", e);
    }
    tokio::spawn(async move {
        let app = Router::new()
            .route("/token", get(handle_gog_token_request));

        let addr = SocketAddr::from(([127, 0, 0, 1], 80));
        
        // Create a Tokio TcpListener for Axum
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("[HTTP SERVER] Failed to bind to {}: {}", addr, e);
                return; // Exit this task if binding fails
            }
        };
        info!("[HTTP SERVER] Listening on {}", addr);

        // Use axum::serve for hyper 1.x compatibility
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move {
                http_server_shutdown_token.cancelled().await;
                info!("[HTTP SERVER] Shutting down gracefully.");
            })
            .await
            .unwrap_or_else(|e| error!("[HTTP SERVER] Server error: {}", e));
    });

    let (overlay_event_sender_main, _) = broadcast::channel::<(u32, OverlayPeerMessage)>(16);
    let (topic_sender, _) = tokio::sync::broadcast::channel::<PusherEvent>(20); // If still used by TCP handlers
    let (client_exit, mut con_exit_recv) = tokio::sync::mpsc::channel::<()>(10);
    let socket_shutdown = tcp_server_shutdown_token.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen to ctrl c signal");
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
    loop {
        tokio::select! {
            biased; // Prioritize shutdown signal
            _ = socket_shutdown.cancelled() => {
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
                        let handler_shutdown = socket_shutdown.clone();
                        let handler_user_info = cloned_user_info.clone();
                        let handler_client_exit = client_exit.clone();
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
                socket_shutdown.cancel(); // This will trigger the main loop break and other cleanup
                break;
            }
        }
    }
    info!("[MAIN] Waiting for all client handlers to complete...");
    join_all(handlers).await;

    if shutdown_token.is_cancelled() {
        info!("[MAIN] Shutdown process was initiated. Allowing cleanup tasks to run.");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    info!("CometOffline shutting down completely.");
}
