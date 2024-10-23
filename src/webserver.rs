use crate::appstate::AppState;
use crate::db::{self, Password};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_extra::response::{Css, Html, JavaScript};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::error::Error;
use std::net::SocketAddr;
use std::string::FromUtf8Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Timeout};
use tracing::info;

enum MessageTypes {
    Invalid,
    Auth(String, String), //this one expects a username and a hashed password
    RequestSalt(String), //this one expects a username, if the username exists, it will return the salt, if it doesn't, it will return an error. you cannot hash a password correctly without the salt
    CreateAccount(String, String, String), //this one expects a username and a hashed password and Salt, if there is no issue with the username, it will create the account then log into it
    ChangePassword(String, String, String, String), //username, new password, salt, by the time this is returned the old password has already been checked
}

//this is the entry function for the file, as such, it will choose how everything works from the top, and is in charge of using the config to start a web server, it will not exit unless the start_server function does
pub async fn start_web_server(state: AppState) {
    let (interface_proper, interface_pretty, port) = get_config_values(state.clone()).await;
    info!("Starting web server on {}:{}", interface_pretty, port);

    let address: SocketAddr = SocketAddr::new(interface_proper.parse().expect("config.interface is an invalid IP address\nif you don't care where requests come from, use 0.0.0.0\nto only accept requests from the local network, find your gateway IP and configure interface to match that.\nin a multi-network situation, choose the IP of the network adapter within the network you want to accept requests from, only requests from there would be accepted"), port);

    start_server(state, address).await;
}

//I've reworked the webserver a couple of times, these operations are consistently needed though, so I extracted it into a different function
async fn get_config_values(state: AppState) -> (String, String, u16) {
    let config = state.config.lock().await; //config is inside an arc mutex, we need to lock it, this prevents other code that requires the config from running until we drop it
    let interface_proper = config.interface.clone();
    let interface_pretty = interface_proper.replace("0.0.0.0", "*"); //make the output more pretty, this is worth it, especially such a simple operation
    let port = config.port.clone();
    drop(config); //drop config as soon as we can so we don't hold anything else up
    (interface_proper, interface_pretty, port)
}

//the function below is an internal function to the file, no other files can rely on it, it shall not exit unless the webserver goes down
async fn start_server(state: AppState, address: SocketAddr) {
    let router: Router = create_router(state.clone());

    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

fn create_router(state: AppState) -> Router {
    let router: Router = Router::new()
        .route("/", get(handle_html))
        .route("/index.js", get(handle_javascript))
        .route("/style.css", get(handle_css))
        .route("/ws", get(ws_handler))
        .with_state(state);
    router
}

//the handlers below need no state, they just return their static files respectively
async fn handle_html(State(_): State<AppState>) -> Html<String> {
    let str = include_str!("../html_src/index.html");
    Html(str.to_owned())
}
async fn handle_javascript(State(_): State<AppState>) -> JavaScript<String> {
    let str = include_str!("../html_src/index.js");
    JavaScript(str.to_owned())
}
async fn handle_css(State(_): State<AppState>) -> Css<String> {
    let str = include_str!("../html_src/style.css");
    Css(str.to_owned())
}
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    let l = ws.on_upgrade(move |socket| handle_socket(socket, state.clone()));
    l
}
#[derive(Clone)]
pub struct SocketState {
    pub authenticated: Arc<Mutex<bool>>,
    pub username: Arc<Mutex<Option<String>>>,
    pub tx: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    pub rx: Arc<Mutex<SplitStream<WebSocket>>>,
}

impl SocketState {
    pub fn new(rx: SplitStream<WebSocket>, tx: SplitSink<WebSocket, Message>) -> Self {
        Self {
            authenticated: Arc::new(Mutex::new(false)),
            username: Arc::new(Mutex::new(None)),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

async fn handle_send_task(
    mut global_tx: Receiver<String>,
    mut socket: SocketState,
    id: usize,
    state: AppState,
) {
    //this function will be used to send messages to the client and exit if the client is disconnected
    while let Ok(val) = global_tx.recv().await {
        let message = Message::Text(val);
        let mut sender = socket.tx.lock().await;
        let send_result = sender.send(message).await;
        drop(sender); //drop the lock as soon as we can, we don't need it anymore
        match send_result {
            Ok(_) => (),
            Err(_) => {
                info!("Socket ID: {} has disconnected since last broadcast, terminating listener loop", id);
                break; //break out of the loop if the client is disconnected, no need to keep trying to send messages
            }
        }
    }
}

fn decode_string_from_buffer(buffer: &[u8]) -> Result<String, FromUtf8Error> {
    // Extract the specified slice and attempt to convert it to a UTF-8 string
    let string = String::from_utf8(buffer[0..].to_vec())?;

    Ok(string)
}

async fn send_message_to_tx(socket: &SocketState, message: &str) {
    // Send the message to the tx channel
    let _ = socket
        .tx
        .lock()
        .await
        .send(Message::Text(message.to_string()))
        .await;
}
//function to send a message to a socket
async fn send_message_var_to_tx(socket: &SocketState, message: Message) {
    // Send the message to the tx channel
    let _ = socket.tx.lock().await.send(message).await;
}

async fn handle_recv_task(
    global_tx: Receiver<String>,
    mut socket: SocketState,
    id: usize,
    state: AppState,
) {
    //this function will be used to receive messages from the client and broadcast them to all clients
    //wait for message
    let socket_clone = socket.clone();
    loop {
        //wait for 10ms for a message, if not do nothing, will also let us disconnect if the client is disconnected
        let mut rx = socket_clone.rx.lock().await;
        let message: Message = match timeout(Duration::from_millis(10), rx.next()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(e))) => {
                info!(
                    "Socket ID: {} encountered an error while receiving a message: {}",
                    id, e
                );
                continue;
            }
            Ok(None) => continue,
            Err(_) => {
                info!("Socket ID: {} has disconnected since last broadcast, terminating listener loop", id);
                state.remove_socket(id).await;
                break;
            }
        };
        drop(rx); //drop the lock as soon as we can, we don't need it anymore
                  //we are expecting all our messages in binary format, so we need to decode them, for starters there is a header taking two bytes, this is expected to be 0x5F10,
                  //then there is an opcode which specifies type, this is 16 bytes, then the rest is up to the message type, all messages are in big endian
        let message = match message {
            Message::Binary(message) => message,
            _ => {
                send_message_to_tx(&socket, "Invalid Message").await;
                continue;
            }
        };
        //check header, make sure it is 0x5F10
        if message[0] != 0x5F || message[1] != 0x10 {
            send_message_to_tx(&socket, "Invalid Header").await;
            continue;
        }
        //check opcode
        let opcode: u16 = u16::from_be_bytes([message[2], message[3]]);
        let message = &message[4..];
        let message: MessageTypes =
            check_message(opcode, message, id, socket.clone(), state.clone()).await;
        match message {
            MessageTypes::Auth(username, password_hash) => {
                //user has already been checked, so we just need to verify the password
                let auth = db::check_password(&state.db, username.as_str(), password_hash.as_str())
                    .unwrap();
                if auth {
                    send_message_to_tx(&socket, "Authenticated").await;
                    *socket.authenticated.lock().await = true;
                    *socket.username.lock().await = Some(username);
                } else {
                    send_message_to_tx(&socket, "Incorrect Password").await;
                }
            }
            MessageTypes::RequestSalt(username) => {
                //client is asking for salt from the db, format of message will be salt as unicode
                let salt = db::get_salt(&state.db, username.as_str()).unwrap();
                let salt = salt.as_bytes();
                let mut salt_message = vec![0x5F, 0x10];
                let opcode = 1u16.to_be_bytes();
                //add opcode
                salt_message.extend_from_slice(&opcode);
                //add salt
                salt_message.extend_from_slice(salt);
                let message = Message::Binary(salt_message);
                send_message_var_to_tx(&socket, message).await;
            }
            MessageTypes::CreateAccount(username, password_hash, salt) => {
                //client is asking to create an account, response will be success or failure, success authenticates the user
                let password: Password = Password {
                    hash: password_hash,
                    salt,
                };
                let result = db::add_credentials(&state.db, username.as_str(), password);
                let success = match result {
                    Ok(_) => true,
                    Err(_) => false,
                };
                if success {
                    send_message_to_tx(&socket, "Account Created").await;
                    *socket.authenticated.lock().await = true;
                    *socket.username.lock().await = Some(username);
                } else {
                    send_message_to_tx(&socket, "Account Creation Failed").await;
                }
            }
            MessageTypes::ChangePassword(username, old_hash, new_password_hash, salt) => {
                //client is asking to change their password, response will be success or failure
                let password: Password = Password {
                    hash: new_password_hash,
                    salt,
                };
                let result = db::change_password(&state.db, &username, &old_hash, password);
                let success = match result {
                    Ok(_) => true,
                    Err(_) => false,
                };
                if success {
                    send_message_to_tx(&socket, "Password Changed").await;
                } else {
                    send_message_to_tx(&socket, "Password Change Failed").await;
                }
            }
            _ => (),
        }
    }
}

async fn check_message(
    opcode: u16,
    message: &[u8],
    id: usize,
    socket: SocketState,
    state: AppState,
) -> MessageTypes {
    match opcode {
        1 => {
            //client is asking for salt from the db, format of message will be username as unicode
            let username = match decode_string_from_buffer(message) {
                Ok(username) => username,
                Err(_) => {
                    send_message_to_tx(&socket, "Invalid Username").await;
                    return MessageTypes::Invalid;
                }
            };
            //check if the username is in the database
            let user_exists: bool = db::user_exists(&state.db, username.as_str());
            if !user_exists {
                send_message_to_tx(&socket, "User does not exist").await;
                return MessageTypes::Invalid;
            }
            //create a message type variant and return it
            MessageTypes::RequestSalt(username);
        }
        2 => {
            //check if already authenticated, if so message the client and return invalid
            if *socket.authenticated.lock().await {
                send_message_to_tx(&socket, "Already Authenticated").await;
                return MessageTypes::Invalid;
            }
            //client is sending a login request, format will be u64 username length, u64 password hash length, username, password hash
            //check if the message is long enough to at least store the lengths
            if message.len() < 16 {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //get the username length
            let username_length: u64 = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            //get the password hash length
            let password_hash_length: u64 = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);
            //get the rest of the message
            let message = &message[16..];
            //unicode decode the rest of the message
            let message = match decode_string_from_buffer(message) {
                Ok(message) => message,
                Err(_) => {
                    send_message_to_tx(&socket, "Invalid Message").await;
                    return MessageTypes::Invalid;
                }
            };
            //check if the message is long enough to store the username and password hash
            if message.len() < (username_length + password_hash_length) as usize {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //get the username
            let username = message[0..username_length as usize].to_string();
            //get the password hash
            let password_hash = message[username_length as usize..].to_string();
            //check if the user exists
            let user_exists: bool = db::user_exists(&state.db, username.as_str());
            if !user_exists {
                send_message_to_tx(&socket, "User does not exist").await;
                return MessageTypes::Invalid;
            }
            //return the message type variant
            MessageTypes::Auth(username, password_hash);
        }
        3 => {
            //check if already authenticated, if so message the client and return invalid
            if *socket.authenticated.lock().await {
                send_message_to_tx(&socket, "Already Authenticated").await;
                return MessageTypes::Invalid;
            }
            //client wants to make a new account, format will be u64 username length, u64 password hash length, u64 salt length, username, password hash, salt
            //check if the message is long enough to at least store the lengths
            if message.len() < 24 {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //get the username length
            let username_length: u64 = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            //get the password hash length
            let password_hash_length: u64 = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);
            //get the salt length
            let salt_length: u64 = u64::from_be_bytes([
                message[16],
                message[17],
                message[18],
                message[19],
                message[20],
                message[21],
                message[22],
                message[23],
            ]);
            //get the rest of the message
            let message = &message[24..];
            //unicode decode the rest of the message
            let message = match decode_string_from_buffer(message) {
                Ok(message) => message,
                Err(_) => {
                    send_message_to_tx(&socket, "Invalid Message").await;
                    return MessageTypes::Invalid;
                }
            };
            //check if the message is long enough to store the username, password hash, and salt
            if message.len() < (username_length + password_hash_length + salt_length) as usize {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //seperate the username, password hash, and salt, store as strings
            let username: String = message[0..username_length as usize].to_string();
            let password_hash: String = message[username_length as usize..].to_string();
            let salt: String =
                message[username_length as usize + password_hash_length as usize..].to_string();
            //check if the user already exists
            let user_exists: bool = db::user_exists(&state.db, username.as_str());
            if user_exists {
                send_message_to_tx(&socket, "User already exists").await;
                return MessageTypes::Invalid;
            }
            //return the message type variant
            MessageTypes::CreateAccount(username, password_hash, salt);
        }
        4 => {
            //client wants to change their password, format will be u64 username length, u64 old password hash length, u64 password hash length, u64 new salt length, username, password hash, salt
            //check if already authenticated, if not message the client and return invalid
            if !*socket.authenticated.lock().await {
                send_message_to_tx(&socket, "Not Authenticated").await;
                return MessageTypes::Invalid;
            }
            //check if the message is long enough to at least store the lengths
            if message.len() < 32 {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //get the username length
            let username_length: u64 = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            //get the old password hash length
            let old_password_hash_length: u64 = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);
            //get the new password hash length
            let new_password_hash_length: u64 = u64::from_be_bytes([
                message[16],
                message[17],
                message[18],
                message[19],
                message[20],
                message[21],
                message[22],
                message[23],
            ]);
            //get the salt length
            let salt_length: u64 = u64::from_be_bytes([
                message[24],
                message[25],
                message[26],
                message[27],
                message[28],
                message[29],
                message[30],
                message[31],
            ]);
            //get the rest of the message
            let message = &message[32..];
            //unicode decode the rest of the message
            let message = match decode_string_from_buffer(message) {
                Ok(message) => message,
                Err(_) => {
                    send_message_to_tx(&socket, "Invalid Message").await;
                    return MessageTypes::Invalid;
                }
            };
            //check if the message is long enough to store the username, old password hash, new password hash, and salt
            if message.len()
                < (username_length
                    + old_password_hash_length
                    + new_password_hash_length
                    + salt_length) as usize
            {
                send_message_to_tx(&socket, "Invalid Message").await;
                return MessageTypes::Invalid;
            }
            //seperate the username, old password hash, new password hash, and salt, store as strings
            let username: String = message[0..username_length as usize].to_string();
            let old_password_hash: String = message[username_length as usize
                ..username_length as usize + old_password_hash_length as usize]
                .to_string();
            let new_password_hash: String = message[username_length as usize
                + old_password_hash_length as usize
                ..username_length as usize
                    + old_password_hash_length as usize
                    + new_password_hash_length as usize]
                .to_string();
            let salt: String = message[username_length as usize
                + old_password_hash_length as usize
                + new_password_hash_length as usize..]
                .to_string();
            //check if the user exists
            let user_exists: bool = db::user_exists(&state.db, username.as_str());
            if !user_exists {
                send_message_to_tx(&socket, "User does not exist").await;
                return MessageTypes::Invalid;
            }
            //check if the old password hash is correct
            let old_password_hash_correct: bool =
                db::check_password(&state.db, username.as_str(), old_password_hash.as_str())
                    .unwrap();
            if !old_password_hash_correct {
                send_message_to_tx(&socket, "Old password is incorrect").await;
                return MessageTypes::Invalid;
            }
            //return the message type variant
            return MessageTypes::ChangePassword(
                username,
                old_password_hash,
                new_password_hash,
                salt,
            );
        }
        _ => {}
    }
    MessageTypes::Invalid //default return
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (sender, recievr) = socket.split();
    let socket_state = SocketState::new(recievr, sender);
    let id: usize = state.add_socket(socket_state.clone()).await;
    let mut send_task = tokio::spawn(handle_send_task(
        state.tx.subscribe(),
        socket_state.clone(),
        id.clone(),
        state.clone(),
    ));
    let mut recv_task = tokio::spawn(handle_recv_task(
        state.tx.subscribe(),
        socket_state.clone(),
        id.clone(),
        state.clone(),
    ));
    //wait for either to exit, then terminate the other
    let _ = tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
    //socket is now dead, remove it from the state
    state.remove_socket(id).await;
}
