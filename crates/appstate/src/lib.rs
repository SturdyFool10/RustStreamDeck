
use Config::Config;
use sled::Db;
use std::sync::Arc;
use axum::extract::ws::{Message, WebSocket};
use futures::stream::{SplitSink, SplitStream};
use tokio::sync::{broadcast, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config>>,
    pub socket_state_list: Arc<Mutex<Vec<SocketState>>>,
    pub tx: broadcast::Sender<String>,
    pub db: Db,
}

#[allow(dead_code)] //this is a state api, whether or not it gets used is irrelevant
impl AppState {
    pub fn new(config: Config, db: Db) -> Self {
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
        list.remove(index);
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