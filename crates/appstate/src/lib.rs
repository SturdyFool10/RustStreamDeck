use futures::stream::{SplitSink, SplitStream};
use sled::Db;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::info;
use warp::ws::Message;
use warp::ws::WebSocket;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config::Config>>,
    pub socket_state_list: Arc<Mutex<Vec<SocketState>>>,
    pub tx: broadcast::Sender<String>,
    pub db: Db,
}

#[allow(dead_code)] //this is a state api, whether it gets used is irrelevant
impl AppState {
    pub fn new(config: Config::Config, db: Db) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            socket_state_list: Arc::new(Mutex::new(Vec::new())),
            tx: broadcast::channel(10).0,
            db,
        }
    }

    pub async fn add_socket(&self, socket: SocketState) -> usize {
        let mut list = self.socket_state_list.lock().await;
        list.push(socket);
        list.len() - 1
    }

    pub async fn remove_socket(&self, index: usize) {
        let mut list = self.socket_state_list.lock().await;
        info!("removing socket {} from list", index);
        if index > list.len() - 1 {
            info!(
                "Failed removing socket id: {}, this can leave us with phantom sockets!",
                index
            );
            return;
        } else {
            list.remove(index);
        }
    }

    pub async fn broadcast(&self, message: String) {
        self.tx.send(message).unwrap();
    }
}
#[derive(Clone)]
pub struct SocketState {
    pub authenticated: Arc<Mutex<bool>>,
    pub username: Arc<Mutex<Option<String>>>,
    pub tx: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    pub rx: Arc<Mutex<SplitStream<WebSocket>>>,
}

impl SocketState {
    pub fn new(rx: SplitStream<WebSocket>, tx: SplitSink<WebSocket, Message>) -> Self {
        Self {
            authenticated: Arc::new(Mutex::new(false)),
            username: Arc::new(Mutex::new(None)),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}
