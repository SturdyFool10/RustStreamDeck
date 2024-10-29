use std::{
    fs::File,
    io::{Read, Write},
};
use tracing::{error, info};

pub fn read_file(path: &str) -> Result<String, String> {
    let res = File::open(path);
    match res {
        Ok(mut f) => {
            let mut contents = String::new();
            match f.read_to_string(&mut contents) {
                Ok(_) => {
                    info!("Successfully read file: {}", path);
                    Ok(contents)
                }
                Err(e) => {
                    error!("Failed to read contents of file: {}, Error: {}", path, e);
                    Err(e.to_string()) // Return error as string
                }
            }
        }
        Err(e) => {
            error!("Failed to open file: {}, Error: {}", path, e);
            Err(e.to_string()) // Return error as string
        }
    }
}

pub fn write_to_file(path: &str, contents: &str) -> Result<(), String> {
    match File::create(path) {
        Ok(mut file) => match file.write_all(contents.as_bytes()) {
            Ok(_) => {
                info!("Successfully wrote to file: {}", path);
                Ok(())
            }
            Err(e) => {
                error!("Failed to write to file: {}, Error: {}", path, e);
                Err(e.to_string())
            }
        },
        Err(e) => {
            error!("Failed to create file: {}, Error: {}", path, e);
            Err(e.to_string())
        }
    }
}
