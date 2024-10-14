mod config;
mod files;
mod logging;
mod webserver;

use config::init_config;
use logging::init_logging;

fn main() {
    init_logging();
    let mut config = init_config();
}
