use database::init_db;
use tokio::spawn;
use tracing::*;

use Config::init_config;
use macros::spawn_tasks;
use PrettyLogs::init_logging;
use Webserver::start_web_server;

/*
Welcome to the Streamdeck replacement codebase. the goals of this code is to make a fast, easy
and cheap replacement for the streamdeck.

**Design goals**
- Fast
- Easy to use
- Cheap
- Customizable
- Open Source
- Easy to build
- Panics only when something unrecoverable happens
- Otherwize stable

**TODO**
-Program Website
-handle websockets
-hand-roll own auth system
*/

#[tokio::main]
async fn main() {
    init_logging();
    let config = init_config();
    let db = init_db().await;
    let state: AppState::AppState = AppState::AppState::new(config, db);
    let handles = spawn_tasks!(state, start_web_server);
    info!("Started {} tasks", handles.len());
    for handle in handles {
        handle.await.expect("Task panicked");
    }
}
