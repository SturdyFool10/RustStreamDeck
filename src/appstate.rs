use crate::{config::Config, webserver::SocketState};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config>>,
    pub socket_state_list: Arc<Mutex<Vec<SocketState>>>,
    pub tx: broadcast::Sender<String>,
}

#[allow(dead_code)] //this is a state api, whether or not it gets used is irrelevant
impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            socket_state_list: Arc::new(Mutex::new(Vec::new())),
            tx: broadcast::channel(10).0,
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
