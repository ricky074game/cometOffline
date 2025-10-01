use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::broadcast::{self, Sender};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

lazy_static! {
    static ref TLS_CONFIG: Arc<rustls::ClientConfig> = Arc::new({
        let mut root_store = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(crate::CERT);
        let certs = rustls_pemfile::certs(&mut reader).filter_map(|crt| crt.ok());
        root_store.add_parsable_certificates(certs);
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    });
}

#[allow(dead_code)]
#[derive(Clone)]
pub enum PusherEvent {
    Online,
    Offline,
    Topic(Vec<u8>, String),
}

#[derive(Clone, Debug, Serialize)]
pub struct GameInfo {
    pub game_id: u64,
}

#[derive(Clone, Debug)]
pub enum Notification {
    AchievementUnlocked(Achievement),
    GameConnected(GameInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Achievement {
    pub achievement_id: String,
    pub key: String,
    pub name: String,
    pub description: String,
    pub unlocked_at: Option<i64>,
    pub image_url_unlocked: String,
    pub image_url_locked: String,
}

#[allow(dead_code)]
pub struct NotificationPusherClient {
    pusher_connection: WebSocketStream<MaybeTlsStream<TcpStream>>,
    access_token: String,
    topic_sender: Sender<PusherEvent>,
    shutdown_token: CancellationToken,
}

pub fn spawn_notification_channel() -> (broadcast::Sender<Notification>, broadcast::Receiver<Notification>) {
    broadcast::channel::<Notification>(20)
}

impl NotificationPusherClient {
}
