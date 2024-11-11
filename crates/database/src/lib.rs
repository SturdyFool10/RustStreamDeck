use std::error::Error;

use serde::*;
use sled::Db;

#[derive(Serialize, Deserialize)]
pub struct Password {
    pub salt: String,
    pub hash: String,
}

pub async fn init_db() -> Db {
    //initialize sled db
    let db = sled::open("auth").unwrap();
    db
}
//helper function to check if a user exists, returns true or false
pub fn user_exists(db: &Db, username: &str) -> bool {
    db.contains_key(username).unwrap()
}
//helper function to add credentials to the db, returns Result<bool, String> and errors if the user already exists
pub fn add_credentials(db: &Db, username: &str, password: Password) -> Result<bool, String> {
    if user_exists(db, username) {
        return Err("User already exists".to_string());
    }
    let serialized = serde_json::to_string(&password).unwrap();
    db.insert(username, serialized.as_bytes()).unwrap();
    Ok(true)
}
//helper function to check if the password is correct, returns Result<bool, String> and errors if the user does not exist
pub fn check_password(db: &Db, username: &str, password: &str) -> Result<bool, String> {
    if !user_exists(db, username) {
        return Err("User does not exist".to_string());
    }
    let stored: Password = serde_json::from_slice(&db.get(username).unwrap().unwrap()).unwrap();
    Ok(stored.hash == password)
}
//helper function to change the password, returns Result<bool, String> and errors if the user does not exist, enforcing the old password at code level, Ok(false) if the old password is incorrect
pub fn change_password(
    db: &Db,
    username: &str,
    old_password: &str,
    new_password: Password,
) -> Result<bool, String> {
    if !check_password(db, username, old_password)? {
        return Ok(false);
    }
    let serialized = serde_json::to_string(&new_password).unwrap();
    db.insert(username, serialized.as_bytes()).unwrap();
    Ok(true)
}
//helper function to remove a user, returns Result<bool, String> and errors if the user does not exist, Ok(false) if the password is incorrect
pub fn remove_user(db: &Db, username: &str, password: &str) -> Result<bool, String> {
    if !check_password(db, username, password)? {
        return Ok(false);
    }
    db.remove(username).unwrap();
    Ok(true)
}
//helper function to change the username, returns Result<bool, String> and errors if the user does not exist, Ok(false) if the password is incorrect
pub fn change_username(
    db: &Db,
    old_username: &str,
    new_username: &str,
    password: &str,
) -> Result<bool, Box<dyn Error>> {
    //check if the new username already exists
    if user_exists(db, new_username) {
        return Err("new username already exists".to_string().into());
    }
    //check if the old username exists
    if !user_exists(db, old_username) {
        return Err("User does not exist".to_string().into());
    }
    //check if the password is correct
    if !check_password(db, old_username, password).unwrap_or(false) {
        return Ok(false);
    }
    //get the password object, no need to deserialize it
    let stored = &db.get(old_username)?.unwrap();
    //remove the old username from the db
    db.remove(old_username)?;
    //insert the password object with the new username
    db.insert(new_username, stored)?;
    Ok(true)
}
//helper function to get salt
pub fn get_salt(db: &Db, username: &str) -> Option<String> {
    if !user_exists(db, username) {
        return None;
    }
    let stored: Password = serde_json::from_slice(&db.get(username).unwrap().unwrap()).unwrap();
    Some(stored.salt)
}
