use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    interface: String,
    port: u16,
}
