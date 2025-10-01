use protobuf::{Enum, Message, UnknownValueRef};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::broadcast::{self, Sender};
use tokio::time;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite, MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

use crate::proto::common_utils::ProtoPayload;
use crate::proto::galaxy_protocols_webbroker_service::MessageFromTopic;
use crate::proto::{
    galaxy_common_protocols_connection,
    galaxy_protocols_webbroker_service::{
    },      
    gog_protocols_pb::Header,
};

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

    pub fn parse_message(msg_data: &Vec<u8>) -> Result<ProtoPayload, protobuf::Error> {
        let data = msg_data.as_slice();

        let mut header_size_buf = [0; 2];
        header_size_buf.copy_from_slice(&data[..2]);
        let header_size = u16::from_be_bytes(header_size_buf).into();

        let mut header_buf: Vec<u8> = vec![0; header_size];
        header_buf.copy_from_slice(&data[2..header_size + 2]);

        let header = Header::parse_from_bytes(&header_buf)?;

        let payload_size = header.size().try_into().unwrap();
        let mut payload: Vec<u8> = vec![0; payload_size];

        payload.copy_from_slice(&data[header_size + 2..]);

        Ok(ProtoPayload { header, payload })
    }
}
