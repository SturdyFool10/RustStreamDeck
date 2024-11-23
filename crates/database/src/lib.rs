use rusqlite::Connection;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Password {
    pub salt: String,
    pub hash: String,
    pub security_key: Option<String>,
}

pub async fn init_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open("auth.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            security_key TEXT
        )",
        [],
    )
    .unwrap();
    Arc::new(Mutex::new(conn))
}

pub async fn user_exists(conn: Arc<Mutex<Connection>>, username: &str) -> bool {
    let conn = conn.lock().await;
    let mut stmt = conn
        .prepare("SELECT 1 FROM users WHERE username = ?1")
        .unwrap();
    stmt.exists([username]).unwrap()
}

pub async fn add_credentials(
    conn: Arc<Mutex<Connection>>,
    username: &str,
    password: Password,
) -> Result<bool, String> {
    let exists = user_exists(conn.clone(), username).await;
    if exists {
        return Err("User already exists".to_string());
    }
    let conn = conn.lock().await;
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, security_key) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            username,
            password.hash,
            password.salt,
            password.security_key
        ],
    )
    .unwrap();
    Ok(true)
}

pub async fn is_db_empty(conn: Arc<Mutex<Connection>>) -> bool {
    let conn = conn.lock().await;
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM users").unwrap();
    let count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    count == 0
}

pub async fn check_password(
    conn: Arc<Mutex<Connection>>,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let exists = user_exists(conn.clone(), username).await;
    if !exists {
        return Err("User does not exist".to_string());
    }
    let conn = conn.lock().await;
    let mut stmt = conn
        .prepare("SELECT password_hash FROM users WHERE username = ?1")
        .unwrap();
    let stored_hash: String = stmt.query_row([username], |row| row.get(0)).unwrap();
    Ok(stored_hash == password)
}

pub async fn change_password(
    conn: Arc<Mutex<Connection>>,
    username: &str,
    old_password: &str,
    new_password: Password,
) -> Result<bool, String> {
    let valid = check_password(conn.clone(), username, old_password).await?;
    if !valid {
        return Ok(false);
    }
    let conn = conn.lock().await;
    conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2, security_key = ?3 WHERE username = ?4",
        rusqlite::params![
            new_password.hash,
            new_password.salt,
            new_password.security_key,
            username
        ],
    )
    .unwrap();
    Ok(true)
}

pub async fn remove_user(
    conn: Arc<Mutex<Connection>>,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let valid = check_password(conn.clone(), username, password).await?;
    if !valid {
        return Ok(false);
    }
    let conn = conn.lock().await;
    conn.execute("DELETE FROM users WHERE username = ?1", [username])
        .unwrap();
    Ok(true)
}

pub async fn change_username(
    conn: Arc<Mutex<Connection>>,
    old_username: &str,
    new_username: &str,
    password: &str,
) -> Result<bool, Box<dyn Error>> {
    let new_exists = user_exists(conn.clone(), new_username).await;
    let old_exists = user_exists(conn.clone(), old_username).await;
    let valid = check_password(conn.clone(), old_username, password)
        .await
        .unwrap_or(false);

    if new_exists {
        return Err("new username already exists".to_string().into());
    }
    if !old_exists {
        return Err("User does not exist".to_string().into());
    }
    if !valid {
        return Ok(false);
    }

    let conn = conn.lock().await;
    conn.execute(
        "UPDATE users SET username = ?1 WHERE username = ?2",
        rusqlite::params![new_username, old_username],
    )?;
    Ok(true)
}

pub async fn get_salt(conn: Arc<Mutex<Connection>>, username: &str) -> Option<String> {
    let exists = user_exists(conn.clone(), username).await;
    if !exists {
        return None;
    }
    let conn = conn.lock().await;
    let mut stmt = conn
        .prepare("SELECT salt FROM users WHERE username = ?1")
        .unwrap();
    Some(stmt.query_row([username], |row| row.get(0)).unwrap())
}

pub async fn get_security_key(conn: Arc<Mutex<Connection>>, username: &str) -> Option<String> {
    let exists = user_exists(conn.clone(), username).await;
    if !exists {
        return None;
    }

    let conn = conn.lock().await;
    let mut stmt = match conn.prepare("SELECT security_key FROM users WHERE username = ?1") {
        Ok(stmt) => stmt,
        Err(_) => return None,
    };

    match stmt.query_row([username], |row| row.get::<_, Option<String>>(0)) {
        Ok(result) => result,
        Err(_) => None,
    }
}
