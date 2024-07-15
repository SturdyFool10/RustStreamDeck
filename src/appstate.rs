use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::Config;


pub struct AppState {
    pub config: Arc<Mutex<Config>>,
}
impl AppState {
    pub fn new(config: crate::config::Config) -> Self {
        Self {
            config: Arc::new(Mutex::new(config))
        }
    }
}