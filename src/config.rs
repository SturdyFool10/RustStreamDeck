use std::{error::Error, fs::{File, OpenOptions}, path::Path, io::Write};

use serde::{Serialize, Deserialize};
use crate::files::read_file;


#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    interface: String,
    port: u16,

}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "0.0.0.0".to_string(),
            port: 3216
        }
    }
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let str: String = read_file(path)?;
    let des: Config = serde_json::from_str(str.as_str())?;
    Ok(des)
}
pub fn save_config(config: &Config, path: &str) {
    let file_contents: String = serde_json::to_string_pretty(config).unwrap_or("".to_string());

    let path = Path::new(path);
    let file = if path.exists() {
        OpenOptions::new().write(true).truncate(true).open(path)
    } else {
        File::create(path)
    };

    match file {
        Ok(mut file) => {
            if let Err(e) = file.write_all(file_contents.as_bytes()) {
                eprintln!("Failed to write to file: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Failed to open or create file: {}", e);
        }
    }
}