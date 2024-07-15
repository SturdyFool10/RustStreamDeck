mod macros;
mod files;
mod config;
mod appstate;
mod desktop_configuration_portal;
mod smartphone_display;

use config::{load_config, save_config, Config};
use appstate::AppState;
use desktop_configuration_portal::start_desktop_configuration_server;
use smartphone_display::start_smartphone_display_server;
use tracing::*;
use tokio::spawn;

fn get_config() -> Config {
    info!("Loading Configuration...");
    let config: Config;
    let res = load_config("./config.json");
    match res {
        Ok(val) => {
            config = val;
        },
        Err(_) => {
            info!("Error loading config, Generating default...");
            config = Config::default();
            info!("Saving default configuration to file...");
            save_config(&config, "./config.json");
        }
    }
    config
}

fn setup_tracing() {
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .with_line_number(false)
        .with_file(false)
        .without_time()
        .init();
}

#[tokio::main]
async fn main() {
    setup_tracing();
    info!("Initializing...");
    let config = get_config();
    let state = AppState::new(config);
    //Appstate for shared state is created, we can now start spawning our tasks
    let tasks: Vec<_> = spawn_tasks!(start_smartphone_display_server, start_desktop_configuration_server);
}