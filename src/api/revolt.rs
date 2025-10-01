use crate::api::notification_pusher::{Achievement, Notification};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;
use log::{error, info, warn};

#[derive(Debug, Clone)]
pub struct AchievementsListMessage {
    pub game_id: u64,
    pub achievements: Vec<Achievement>,
}

pub fn spawn_revolt_integration(
    mut notification_rx: broadcast::Receiver<Notification>,
) -> broadcast::Sender<AchievementsListMessage> {
    let (tx, rx): (Sender<TcpStream>, Receiver<TcpStream>) = mpsc::channel();
    let (achievements_tx, _achievements_rx) = broadcast::channel::<AchievementsListMessage>(10);
    let achievements_tx_clone = achievements_tx.clone();

    thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:3333")
            .expect("Failed to bind to port 3333 for RevoltUltimate");
        info!("Listening on port 3333 for RevoltUltimate connection");
        
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    info!("RevoltUltimate connected");
                    let welcome_message = "{\"status\":\"connected\"}\n";
                    if stream.write_all(welcome_message.as_bytes()).is_ok() {
                        info!("Sent connection confirmation to RevoltUltimate.");
                        tx.send(stream)
                            .expect("Failed to send stream to handler thread");
                    } else {
                        error!("Failed to send welcome message to RevoltUltimate, closing connection.");
                    }
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        }
    });

    thread::spawn(move || {
        let mut clients: Vec<TcpStream> = Vec::new();
        
        loop {
            if let Ok(client) = rx.try_recv() {
                clients.push(client);
            }

            if let Ok(notification) = notification_rx.try_recv() {
                let payload_json = match notification {
                    Notification::AchievementUnlocked(achievement) => {
                        info!("Forwarding achievement unlock to RevoltUltimate");
                        json!({
                            "type": "achievement_unlocked",
                            "data": achievement
                        })
                    }
                    Notification::GameConnected(game_info) => {
                        info!("Forwarding game connection info to RevoltUltimate");
                        json!({
                            "type": "game_connected",
                            "data": game_info
                        })
                    }
                };

                let mut payload = serde_json::to_string(&payload_json).unwrap();
                payload.push('\n');

                clients.retain_mut(|client| {
                    if client.write_all(payload.as_bytes()).is_err() {
                        info!("RevoltUltimate disconnected (failed to send).");
                        return false;
                    }
                    true
                });
            }
            clients.retain_mut(|client| {
                if client.set_nonblocking(true).is_err() {
                    return false;
                }

                let mut buffer = vec![0; 8192]; // 8KB buffer
                match client.read(&mut buffer) {
                    Ok(0) => {
                        info!("RevoltUltimate disconnected (connection closed).");
                        false
                    }
                    Ok(bytes_read) => {
                        let data = String::from_utf8_lossy(&buffer[..bytes_read]);
                        for line in data.lines() {
                            if let Err(e) = handle_incoming_message(line, &achievements_tx_clone) {
                                error!("Error handling incoming message: {}", e);
                            }
                        }
                        true
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        true
                    }
                    Err(_) => {
                        info!("RevoltUltimate disconnected (read error).");
                        false
                    }
                }
            });

            thread::sleep(Duration::from_millis(100));
        }
    });

    achievements_tx
}

fn handle_incoming_message(
    message: &str, 
    achievements_tx: &broadcast::Sender<AchievementsListMessage>
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed: Value = serde_json::from_str(message)?;
    
    if let Some(msg_type) = parsed.get("type").and_then(|t| t.as_str()) {
        match msg_type {
            "achievements_list" => {
                let game_id = parsed.get("game_id")
                    .and_then(|id| id.as_u64())
                    .ok_or("Missing or invalid game_id")?;
                
                let achievements_data = parsed.get("data")
                    .and_then(|d| d.as_array())
                    .ok_or("Missing or invalid achievements data")?;
                
                let mut achievements = Vec::new();
                for ach_data in achievements_data {
                    let achievement: Achievement = serde_json::from_value(ach_data.clone())?;
                    achievements.push(achievement);
                }
                
                let achievements_msg = AchievementsListMessage {
                    game_id,
                    achievements: achievements.clone(),
                };
                
                if let Err(e) = achievements_tx.send(achievements_msg) {
                    error!("Failed to broadcast achievements list: {}", e);
                }
                
                info!("Received and processed achievements list for game_id: {} ({} achievements)", game_id, achievements.len());
            }
            _ => {
                warn!("Unknown message type: {}", msg_type);
            }
        }
    }
    
    Ok(())
}