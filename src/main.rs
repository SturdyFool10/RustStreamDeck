mod appstate;
mod config;
mod files;
mod logging;
mod macros;
mod webserver;

use tokio::spawn;
use tracing::*;

use appstate::AppState;
use config::init_config;
use logging::init_logging;
use webserver::start_web_server;

#[tokio::main]
async fn main() {
    init_logging();
    let mut config = init_config();
    let mut state: AppState = AppState::new(config);
    let mut handles = spawn_tasks!(state, start_web_server);
    info!("Started {} tasks", handles.len());
}
