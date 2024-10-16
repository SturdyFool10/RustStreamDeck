mod appstate;
mod config;
mod files;
mod logging;
mod macros;
mod proto;
mod webserver;

use tokio::spawn;
use tracing::*;

use appstate::AppState;
use config::init_config;
use logging::init_logging;
use webserver::start_web_server;

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
    let state: AppState = AppState::new(config);
    let mut handles = spawn_tasks!(state, start_web_server);
    info!("Started {} tasks", handles.len());
    for handle in handles {
        handle.await.expect("Task panicked");
    }
}
