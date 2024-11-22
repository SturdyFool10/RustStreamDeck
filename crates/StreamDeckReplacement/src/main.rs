use database::init_db;
use std::process::exit;
use tracing::*;

use config::init_config;
use macros::{await_any, spawn_tasks};
use pretty_logs::init_logging;
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
- Otherwise stable

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
    let state: app_state::AppState = app_state::AppState::new(config, db);
    let mut handles = spawn_tasks!(state, start_web_server);
    info!("Started {} tasks", handles.len());
    await_any!(handle_panicked_task, &mut handles[0]);
}

async fn handle_panicked_task() {
    error!("A task has panicked, exiting...");
    exit(1);
}
