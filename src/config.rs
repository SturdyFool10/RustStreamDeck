use crate::files::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use tracing::{error, info, warn};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub interface: String,
    pub port: u16,
}

pub fn init_config() -> Config {
    let config_path: &str = "./config.json";
    //the steps for this are as follows: check if ./config.json exists, if not create it and set it to the value of the file defaultconfig.json at compile time using include_str!(), read the file, parse to json, if it is not valid json, spit out an error and panic
    let file_exists = Path::new(config_path).exists();
    if (!file_exists) {
        let new_contents = include_str!("../src/defaultconfig.json");
        warn!("no configuration file found, making one using the default...");
        let res = write_to_file(config_path, new_contents);
        match res {
            Err(e) => {
                error!("Error trying to write the default config to a file: {}", e);
                panic!("{}", e);
            }
            _ => {}
        }
    }
    let res = read_file(config_path);
    match (res) {
        Ok(value) => {
            let res: Result<Config, serde_json::Error> = serde_json::from_str(value.as_str());
            match (res) {
                Ok(conf) => conf,
                Err(e) => {
                    error!("Error Interpreting Config: {}", e);
                    panic!("{}", e);
                }
            }
        }
        Err(e) => {
            error!(
                "failed to load the config file after checking if it exists, Error: {}",
                e
            );
            panic!("{}", e);
        }
    }
}
