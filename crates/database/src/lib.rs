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
    conn.execute(include_str!("sql_queries/create_tables.sql"), [])
        .unwrap();
    Arc::new(Mutex::new(conn))
}

pub async fn user_exists(conn: Arc<Mutex<Connection>>, username: &str) -> bool {
    let conn = conn.lock().await;
    let mut stmt = conn
        .prepare(include_str!("sql_queries/user_exists.sql"))
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
        include_str!("sql_queries/add_credentials.sql"),
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
    let mut stmt = conn
        .prepare(include_str!("sql_queries/is_db_empty.sql"))
        .unwrap();
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
        .prepare(include_str!("sql_queries/check_password.sql"))
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
        include_str!("sql_queries/change_password.sql"),
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
    conn.execute(include_str!("sql_queries/remove_user.sql"), [username])
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
        include_str!("sql_queries/change_username.sql"),
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
        .prepare(include_str!("sql_queries/get_salt.sql"))
        .unwrap();
    Some(stmt.query_row([username], |row| row.get(0)).unwrap())
}

pub async fn get_security_key(conn: Arc<Mutex<Connection>>, username: &str) -> Option<String> {
    let exists = user_exists(conn.clone(), username).await;
    if !exists {
        return None;
    }

    let conn = conn.lock().await;
    let mut stmt = match conn.prepare(include_str!("sql_queries/get_security_key.sql")) {
        Ok(stmt) => stmt,
        Err(_) => return None,
    };

    match stmt.query_row([username], |row| row.get::<_, Option<String>>(0)) {
        Ok(result) => result,
        Err(_) => None,
    }
}
