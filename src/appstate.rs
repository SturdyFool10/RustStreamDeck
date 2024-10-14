use crate::config::Config;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config>>,
}
impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
        }
    }
}
