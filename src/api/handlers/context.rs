use std::collections::HashMap;
use std::collections::HashSet;

use crate::api::gog::overlay::OverlayPeerMessage;
use crate::api::notification_pusher::{Achievement, Notification}; // Import Achievement
use crate::constants::TokenStorage;
use crate::db;
use crate::api::revolt::AchievementsListMessage;
use derive_getters::Getters;
use log::info;
use sqlx::SqlitePool;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex, MutexGuard};

pub struct State {
    is_online: bool,
    client_identified: bool,
    client_id: Option<String>,
    client_secret: Option<String>,
    subscribed_topics: HashSet<String>,
    updated_achievements: bool,
    updated_stats: bool,
    updated_leaderboards: bool,
    pid: u32,
}

#[derive(Getters)]
pub struct HandlerContext {
    socket: Mutex<TcpStream>,
    token_store: TokenStorage,
    overlay_sender: broadcast::Sender<(u32, OverlayPeerMessage)>,
    overlay_listener: Mutex<String>,
    #[getter(skip)]
    db_connection: Mutex<Option<SqlitePool>>,
    #[getter(skip)]
    state: Mutex<State>,
    notification_tx: broadcast::Sender<Notification>,
    achievements_from_revolt_rx: Mutex<broadcast::Receiver<AchievementsListMessage>>,
    achievement_id_mapping: Mutex<HashMap<String, u64>>,
    cached_revolt_achievements: Mutex<Option<Vec<Achievement>>>, // FIXED: Changed Notification to Achievement
}

impl HandlerContext {
    pub fn new(
        socket: TcpStream,
        token_store: TokenStorage,
        overlay_event_sender: broadcast::Sender<(u32, OverlayPeerMessage)>,
        notification_tx: broadcast::Sender<Notification>,
        achievements_from_revolt_rx: broadcast::Receiver<AchievementsListMessage>,
    ) -> Self {
        let state = Mutex::new(State {
            is_online: false,
            client_identified: false,
            client_id: None,
            client_secret: None,
            subscribed_topics: HashSet::new(),
            updated_achievements: false,
            updated_stats: false,
            updated_leaderboards: true,
            pid: 0,
        });
        Self {
            socket: Mutex::new(socket),
            token_store,
            overlay_sender: overlay_event_sender,
            db_connection: Mutex::new(None),
            overlay_listener: Mutex::new(String::default()),
            state,
            notification_tx,
            achievements_from_revolt_rx: Mutex::new(achievements_from_revolt_rx),
            achievement_id_mapping: Mutex::new(HashMap::new()),
            cached_revolt_achievements: Mutex::new(None), // FIXED: Changed Notification to Achievement
        }
    }

    pub async fn socket_mut(&self) -> MutexGuard<'_, TcpStream> {
        self.socket.lock().await
    }

    pub async fn socket_read_u16(&self) -> Result<u16, std::io::Error> {
        self.socket.lock().await.read_u16().await
    }

    pub async fn identify_client(&self, client_id: &str, client_secret: &str, pid: u32) {
        let mut state = self.state.lock().await;
        state.client_identified = true;
        state.client_id = Some(client_id.to_string());
        state.client_secret = Some(client_secret.to_string());
        state.pid = pid;
    }

    pub async fn set_online(&self) {
        self.state.lock().await.is_online = true
    }

    pub async fn subscribe_topic(&self, topic: String) {
        self.state.lock().await.subscribed_topics.insert(topic);
    }

    pub async fn is_subscribed(&self, topic: &String) -> bool {
        self.state.lock().await.subscribed_topics.contains(topic)
    }

    pub async fn set_offline(&self) {
        self.state.lock().await.is_online = false
    }

    pub async fn set_updated_achievements(&self, value: bool) {
        self.state.lock().await.updated_achievements = value
    }
    pub async fn set_updated_stats(&self, value: bool) {
        self.state.lock().await.updated_stats = value
    }
    pub async fn set_updated_leaderboards(&self, value: bool) {
        self.state.lock().await.updated_leaderboards = value
    }

    pub async fn setup_database(&self, client_id: &str, user_id: &str) -> Result<(), sqlx::Error> {
        let mut db_con = self.db_connection.lock().await;
        if db_con.is_some() {
            return Ok(());
        }
        let connection = db::gameplay::setup_connection(client_id, user_id).await?;
        *db_con = Some(connection);

        let pool = db_con.clone().unwrap();
        let mut connection = pool.acquire().await?;
        sqlx::query(db::gameplay::SETUP_QUERY)
            .execute(&mut *connection)
            .await?;

        let _ = sqlx::query("INSERT INTO database_info VALUES ('language', $1) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(crate::LOCALE.as_str())
            .execute(&mut *connection)
            .await;

        Ok(())
    }

    pub async fn db_connection(&self) -> SqlitePool {
        let connection = self.db_connection.lock().await.clone();
        connection.unwrap()
    }

    pub async fn client_id(&self) -> Option<String> {
        self.state.lock().await.client_id.clone()
    }

    pub async fn client_secret(&self) -> Option<String> {
        self.state.lock().await.client_secret.clone()
    }

    pub async fn is_online(&self) -> bool {
        self.state.lock().await.is_online
    }

    pub async fn client_identified(&self) -> bool {
        self.state.lock().await.client_identified
    }

    pub async fn updated_achievements(&self) -> bool {
        self.state.lock().await.updated_achievements
    }
    pub async fn updated_stats(&self) -> bool {
        self.state.lock().await.updated_stats
    }
    pub async fn updated_leaderboards(&self) -> bool {
        self.state.lock().await.updated_leaderboards
    }

    pub async fn get_pid(&self) -> u32 {
        self.state.lock().await.pid
    }

    pub async fn register_overlay_listener(&self, pid: u32, listener: String) {
        let mut ov_listener = self.overlay_listener.lock().await;
        self.state.lock().await.pid = pid;
        *ov_listener = listener;
    }

    pub fn notification_sender(&self) -> &broadcast::Sender<Notification> {
        &self.notification_tx
    }
    
    pub async fn try_receive_achievements(&self) -> Option<AchievementsListMessage> {
        let mut rx = self.achievements_from_revolt_rx.lock().await;
        rx.try_recv().ok()
    }

    pub async fn cache_revolt_achievements(&self, achievements: Vec<Achievement>) { // FIXED: Changed Notification to Achievement
        let mut cache = self.cached_revolt_achievements.lock().await;
        *cache = Some(achievements);
        info!("Cached {} achievements from RevoltUltimate", cache.as_ref().unwrap().len());
    }

    pub async fn get_cached_revolt_achievements(&self) -> Option<Vec<Achievement>> { // FIXED: Changed Notification to Achievement
        let cache = self.cached_revolt_achievements.lock().await;
        cache.clone()
    }

    pub async fn get_achievement_id(&self, achievement_key: &str) -> u64 {
        let mut mapping = self.achievement_id_mapping.lock().await;
        if let Some(&id) = mapping.get(achievement_key) {
            return id;
        }
        let id = string_to_achievement_id(achievement_key);
        mapping.insert(achievement_key.to_string(), id);
        info!("Generated achievement ID {} for key '{}'", id, achievement_key);
        id
    }
    
    pub async fn get_achievement_key_by_id(&self, achievement_id: u64) -> Option<String> {
        let mapping = self.achievement_id_mapping.lock().await;
        mapping.iter()
            .find(|(_, &id)| id == achievement_id)
            .map(|(key, _)| key.clone())
    }
}

fn string_to_achievement_id(achievement_key: &str) -> u64 {
    let bytes = achievement_key.as_bytes();
    let mut id: u64 = 5381;
    for &byte in bytes {
        id = id.wrapping_mul(33).wrapping_add(byte as u64);
    }
    if id == 0 { 1 } else { id }
}
