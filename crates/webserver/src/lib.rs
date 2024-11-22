use database::Password;
use futures::{SinkExt, StreamExt};
use local_ip_address::list_afinet_netifas;
use rcgen::{
    date_time_ymd, generate_simple_self_signed, Certificate, CertificateParams, DnType, KeyPair,
};
use serde::Serialize;
use std::fs::{remove_file, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;
use std::{net::SocketAddr, string::FromUtf8Error};
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;
use tracing::{error, info};
use warp::filters::ws::{Message, WebSocket};
use warp::{reply, Filter as _};
use FileHelpers::*;
#[derive(Debug)]
enum MessageTypes {
    Invalid,
    Auth(String, String), //this one expects a username and a hashed password
    RequestSalt(String), //this one expects a username, if the username exists, it will return the salt, if it doesn't, it will return an error. you cannot hash a password correctly without the salt
    CreateAccount(String, String, String), //this one expects a username and a hashed password and Salt, if there is no issue with the username, it will create the account then log into it
    ChangePassword(String, String, String, String), //username, new password, salt, by the time this is returned the old password has already been checked
}

//this is the entry function for the file, as such, it will choose how everything works from the top, and is in charge of using the config to start a web server, it will not exit unless the start_server function does
pub async fn start_web_server(state: AppState::AppState) {
    let (interface_proper, interface_pretty, port) = get_config_values(state.clone()).await;
    info!("Starting web server on {}:{}", interface_pretty, port);
    //check for certs and keys, if they exist, use them, if they don't, generate them
    check_certs();
    let address: SocketAddr = SocketAddr::new(interface_proper.parse().expect("config.interface is an invalid IP address\nif you don't care where requests come from, use 0.0.0.0\nto only accept requests from the local network, find your gateway IP and configure interface to match that.\nin a multi-network situation, choose the IP of the network adapter within the network you want to accept requests from, only requests from there would be accepted"), port);
    start_server(state, address).await;
}

fn check_certs() {
    if !check_file_exists("certs/cert.pem")
        || !check_file_exists("certs/key.pem")
        || !check_file_exists("certs/cert.der")
        || !check_file_exists("certs/key.der")
    {
        info!("one of the cert files was missing, so I need to regenerate all of them");
        generate_cert_and_key();
    }
}

fn generate_cert_and_key() -> Result<(), Box<dyn std::error::Error>> {
    let subject_alts = get_local_addresses();
    let mut params: CertificateParams = Default::default();
    let key_pair = KeyPair::generate()?;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(4023, 1, 1);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Sturdy LLC");
    params
        .distinguished_name
        .push(DnType::CommonName, "Deckify");
    params.subject_alt_names = subject_alts
        .iter()
        .map(|x| rcgen::SanType::DnsName(x.as_str().try_into().unwrap()))
        .collect();
    let cert = params.self_signed(&key_pair).unwrap();
    //check if the /certs folder exists, if it doesn't, create it
    if !check_file_exists("/certs") {
        std::fs::create_dir("/certs").unwrap();
    }

    let pem_serial = cert.pem();
    write_to_file("certs/cert.pem", &pem_serial).unwrap();
    let der = cert.der();
    let der_bytes = der.bytes();
    write_bytes_to_file(der_bytes, "certs/cert.der").unwrap();
    let key_serial = key_pair.serialize_pem();
    write_to_file("certs/key.pem", &key_serial).unwrap();
    let key_der = key_pair.serialize_der();
    std::fs::write("certs/key.der", key_der).unwrap();
    Ok(())
}

fn get_local_addresses() -> Vec<String> {
    let mut addresses: Vec<String> = list_afinet_netifas()
        .unwrap()
        .into_iter()
        .map(|(_, ip)| ip.to_string())
        .collect();

    // Adding common localhost addresses for both IPv4 and IPv6
    addresses.push("localhost".to_string()); // IPv4 localhost
    addresses.push("::1".to_string()); // IPv6 localhost

    addresses
}

//I've reworked the webserver a couple of times, these operations are consistently needed though, so I extracted it into a different function
async fn get_config_values(state: AppState::AppState) -> (String, String, u16) {
    let config = state.config.lock().await; //config is inside an arc mutex, we need to lock it, this prevents other code that requires the config from running until we drop it
    let interface_proper = config.interface.clone();
    let interface_pretty = interface_proper.replace("0.0.0.0", "*"); //make the output more pretty, this is worth it, especially such a simple operation
    let port = config.port.clone();
    drop(config); //drop config as soon as we can so we don't hold anything else up
    (interface_proper, interface_pretty, port)
}

//the function below is an internal function to the file, no other files can rely on it, it shall not exit unless the webserver goes down
async fn start_server(state: AppState::AppState, address: SocketAddr) {
    const JS_CONTENT: &str = include_str!("../html_src/index.js");
    const CSS_CONTENT: &str = include_str!("../html_src/style.css");
    const HTML_CONTENT: &str = include_str!("../html_src/index.html");
    const CRYPTO_CONTENT: &str = include_str!("../html_src/crypto.min.js");
    const JQUERY_CONTENT: &str = include_str!("../html_src/jquery.min.js");
    const SECURITY_KEY_SVG_CONTENT: &str = include_str!("../html_src/security_key.svg");
    // Perform any necessary certificate checks
    check_certs();

    let cert = "certs/cert.pem";
    let key = "certs/key.pem";
    // Route for `index.js`
    let js_route = warp::path("index.js").map(|| serve_javascript(JS_CONTENT));
    // Route for `style.css`
    let css_route = warp::path("style.css").map(|| serve_css(CSS_CONTENT));
    // Route for `crypto.min.js`
    let crypto_route = warp::path("crypto.js").map(|| serve_javascript(CRYPTO_CONTENT));
    // Route for `jquery.min.js`
    let jquery_route = warp::path("jquery.js").map(|| serve_javascript(JQUERY_CONTENT));
    //route for security key.svg
    let svg_route = warp::path("security_key.svg").map(|| serve_svg(SECURITY_KEY_SVG_CONTENT));
    // Route for WebSocket `ws`
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(warp::any().map(move || state.clone()))
        .map(|ws: warp::ws::Ws, state: AppState::AppState| {
            ws.on_upgrade(move |socket| handle_socket(socket, state))
        });
    // Route for serving the HTML at the root path
    let root_route = warp::path::end().map(|| warp::reply::html(HTML_CONTENT));

    // Merge all routes together
    let routes = js_route
        .or(css_route)
        .or(crypto_route)
        .or(jquery_route)
        .or(ws_route)
        .or(svg_route)
        .or(root_route);

    // Serve with TLS
    warp::serve(routes)
        .tls()
        .cert_path(cert)
        .key_path(key)
        .run(address)
        .await;
}

fn serve_javascript(js_content: &'static str) -> impl warp::Reply {
    reply::with_header(
        reply::html(js_content),
        "Content-Type",
        "application/javascript",
    )
}

fn serve_svg(svg_content: &'static str) -> impl warp::Reply {
    reply::with_header(reply::html(svg_content), "Content-Type", "image/svg+xml")
}

fn serve_css(css_content: &'static str) -> impl warp::Reply {
    reply::with_header(reply::html(css_content), "Content-Type", "text/css")
}

async fn handle_send_task(
    mut global_tx: Receiver<String>,
    socket: AppState::SocketState,
    id: usize,
    _state: AppState::AppState,
) {
    //this function will be used to send messages to the client and exit if the client is disconnected
    while let Ok(val) = global_tx.recv().await {
        let message = Message::text(val);
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

async fn send_message_to_tx(socket: &AppState::SocketState, message: &str) {
    // Send the message to the tx channel
    let _ = socket
        .tx
        .lock()
        .await
        .send(Message::text(message.to_string()))
        .await;
}
//function to send a binary message to a socket
async fn send_binary_message_to_tx(socket: &AppState::SocketState, message: &[u8]) {
    // Send the message to the tx channel
    let _ = socket
        .tx
        .lock()
        .await
        .send(Message::binary(message.to_vec()))
        .await;
}

//helper function to de-duplicate code for sending a result packet
async fn send_result_packet(socket: AppState::SocketState, msg: String) {
    let mut tx = socket.tx.lock().await;
    let mut buffer: Vec<u8> = vec![0x5F, 0x10];
    let opcode = u16::to_be_bytes(0x02u16);
    let msg_len = u64::to_be_bytes(msg.len() as u64);
    let msg_bytes = &msg.as_bytes();
    buffer.extend_from_slice(&opcode);
    buffer.extend_from_slice(&msg_len);
    buffer.extend_from_slice(&msg_bytes);
    let res = tx.send(Message::binary(buffer)).await;
    match res {
        Ok(_) => (),
        Err(_) => {}
    }
}

async fn handle_recv_task(
    _global_tx: Receiver<String>,
    socket: AppState::SocketState,
    id: usize,
    state: AppState::AppState,
) {
    let socket_clone = socket.clone();
    loop {
        let mut rx = socket_clone.rx.lock().await;
        let message: Message = match timeout(Duration::from_millis(10), rx.next()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(e))) => {
                info!(
                    "Socket ID: {} encountered an error while receiving a message: {}",
                    id, e
                );
                break;
            }
            Ok(None) => continue,
            Err(_val) => {
                continue;
            }
        };
        drop(rx); //drop the lock as soon as we can, we don't need it anymore
                  //we are expecting all our messages in binary format, so we need to decode them, for starters there is a header taking two bytes, this is expected to be 0x5F10,
                  //then there is an opcode which specifies type, this is 16 bytes, then the rest is up to the message type, all messages are in big endian
                  //check if the message is empty text, this can be caused by the timeout running out of time, we do this to ensure mutexes are dropped often so other tasks only wait 10ms max
        if message.is_text() {
            let msg = message.to_str().unwrap_or("");
            if msg == "" {
                continue;
            }
        }
        if message.is_binary() {
            let message = message.as_bytes();
            if message[0] != 0x5F || message[1] != 0x10 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                continue;
            }
            let opcode: u16 = u16::from_be_bytes([message[2], message[3]]);
            let message = &message[4..];
            let message: MessageTypes =
                check_message(opcode, message, id, socket.clone(), state.clone()).await;
            match message {
                MessageTypes::Auth(username, password_hash) => {
                    //user has already been checked, so we just need to verify the password
                    let auth = database::check_password(
                        &state.db,
                        username.as_str(),
                        password_hash.as_str(),
                    )
                    .unwrap();
                    if auth {
                        send_result_packet(socket.clone(), "authed".to_string()).await;
                        *socket.authenticated.lock().await = true;
                        *socket.username.lock().await = Some(username);
                    } else {
                        send_result_packet(socket.clone(), "Incorrect Password".to_string()).await
                    }
                }
                MessageTypes::RequestSalt(username) => {
                    //client is asking for salt from the db, format of message will be salt as Unicode
                    let salt = database::get_salt(&state.db, username.as_str()).unwrap();
                    let salt = salt.as_bytes();
                    let mut salt_message = vec![0x5F, 0x10];
                    let opcode = 1u16.to_be_bytes();
                    //add opcode
                    salt_message.extend_from_slice(&opcode);
                    //add salt
                    salt_message.extend_from_slice(salt);
                    send_binary_message_to_tx(&socket, &salt_message).await;
                }
                MessageTypes::CreateAccount(username, password_hash, salt) => {
                    //client is asking to create an account, response will be success or failure, success authenticates the user
                    let password: Password = Password {
                        hash: password_hash,
                        salt,
                    };
                    let result = database::add_credentials(&state.db, username.as_str(), password);
                    let success = match result {
                        Ok(_) => true,
                        Err(_) => false,
                    };
                    if success {
                        send_result_packet(socket.clone(), "acct_created".to_string()).await;
                        send_result_packet(socket.clone(), "authed".to_string()).await;
                        *socket.authenticated.lock().await = true;
                        *socket.username.lock().await = Some(username);
                    } else {
                        send_result_packet(socket.clone(), "acct_gen_fail".to_string()).await
                    }
                }
                MessageTypes::ChangePassword(username, old_hash, new_password_hash, salt) => {
                    //client is asking to change their password, response will be success or failure
                    let password: Password = Password {
                        hash: new_password_hash,
                        salt,
                    };
                    let result =
                        database::change_password(&state.db, &username, &old_hash, password);
                    let success = match result {
                        Ok(_) => true,
                        Err(_) => false,
                    };
                    if success {
                        send_result_packet(socket.clone(), "pass_chngd".to_string()).await
                    } else {
                        send_result_packet(socket.clone(), "pass_chng_fail".to_string()).await
                    }
                }
                _ => (),
            }
        }
    }
}

async fn check_message(
    opcode: u16,
    message: &[u8],
    _id: usize,
    socket: AppState::SocketState,
    state: AppState::AppState,
) -> MessageTypes {
    let ret: MessageTypes = match opcode {
        1 => {
            let mut result: MessageTypes = MessageTypes::Invalid;
            let mut done = false;
            //client is asking for salt from the db, format of message will be username as unicode
            let username = match decode_string_from_buffer(message) {
                Ok(username) => username,
                Err(_) => {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    done = true;
                    "".to_owned()
                }
            };
            if !done {
                //check if the username is in the database
                let user_exists: bool = database::user_exists(&state.db, username.as_str());
                if !user_exists {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    done = true;
                }
                //create a message type variant and return it
                if !done {
                    result = MessageTypes::RequestSalt(username);
                    done = true;
                }
            }
            result
        }
        2 => {
            //check if already authenticated, if so message the client and return invalid
            if *socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_already_authenticated".to_string()).await;
                return MessageTypes::Invalid;
            }
            //client is sending a login request, format will be u64 username length, u64 password hash length, username, password hash
            //check if the message is long enough to at least store the lengths
            if message.len() < 16 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
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
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    return MessageTypes::Invalid;
                }
            };
            //check if the message is long enough to store the username and password hash
            if message.len() != (username_length + password_hash_length) as usize {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }
            //get the username
            let username = message[0..username_length as usize].to_string();
            //get the password hash
            let password_hash = message[username_length as usize..].to_string();
            //check if the user exists
            let user_exists: bool = database::user_exists(&state.db, username.as_str());
            if !user_exists {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }
            //return the message type variant
            MessageTypes::Auth(username, password_hash)
        }
        3 => {
            // Define ret and done at the top of the function
            let mut ret = MessageTypes::Invalid;
            let mut done = false;

            // Check if already authenticated
            if *socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_already_authenticated".to_string()).await;
                done = true;
            }

            // Proceed only if not done
            if !done {
                // Check message length to contain at least the lengths
                if message.len() < 24 {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    done = true;
                }
            }

            // Proceed only if not done
            if !done {
                // Get username length
                let username_length: u64 = u64::from_be_bytes([
                    message[0], message[1], message[2], message[3], message[4], message[5],
                    message[6], message[7],
                ]);

                // Get password hash length
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

                // Get salt length
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

                // Get the remaining message
                let message = &message[24..];

                // Decode the message, handling errors
                let message = match decode_string_from_buffer(message) {
                    Ok(decoded_message) => decoded_message,
                    Err(_) => {
                        send_result_packet(socket.clone(), "invalid".to_string()).await;
                        done = true;
                        String::new() // Default empty string in case of error
                    }
                };

                // Proceed only if not done
                if !done {
                    // Check if the message length is sufficient for username, password hash, and salt
                    if message.len()
                        < (username_length + password_hash_length + salt_length) as usize
                    {
                        send_result_packet(socket.clone(), "invalid".to_string()).await;
                        done = true;
                    }
                }

                // Proceed only if not done
                if !done {
                    // Extract username, password hash, and salt
                    let username = message[0..username_length as usize].to_string();
                    let password_hash = message[username_length as usize
                        ..(username_length + password_hash_length) as usize]
                        .to_string();
                    let salt =
                        message[(username_length + password_hash_length) as usize..].to_string();

                    // Check if the user already exists in the database
                    if database::user_exists(&state.db, username.as_str()) {
                        send_result_packet(socket.clone(), "err_username_taken".to_string()).await;
                        done = true;
                    } else {
                        // If everything is valid, set the return message type
                        ret = MessageTypes::CreateAccount(username, password_hash, salt);
                    }
                }
            }

            // Return the final message type based on validity
            ret
        }
        4 => {
            let mut result = MessageTypes::Invalid;
            let mut done = false;
            //client wants to change their password, format will be u64 username length, u64 old password hash length, u64 password hash length, u64 new salt length, username, password hash, salt
            //check if already authenticated, if not message the client and return invalid
            if !*socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_not_authorized".to_string()).await;
                done = true;
            }
            //check if the message is long enough to at least store the lengths
            if message.len() < 32 && !done {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                done = true;
            }
            if !done {
                //get the username length
                let username_length: u64 = u64::from_be_bytes([
                    message[0], message[1], message[2], message[3], message[4], message[5],
                    message[6], message[7],
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
                        send_result_packet(socket.clone(), "invalid".to_string()).await;

                        done = true;
                        "".to_string()
                    }
                };
                //check if the message is long enough to store the username, old password hash, new password hash, and salt
                if message.len()
                    < (username_length
                        + old_password_hash_length
                        + new_password_hash_length
                        + salt_length) as usize
                    && !done
                {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    done = true;
                }
                //separate the username, old password hash, new password hash, and salt, store as strings
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
                let user_exists: bool = database::user_exists(&state.db, username.as_str());
                if !user_exists && !done {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    done = true;
                }
                //check if the old password hash is correct
                let old_password_hash_correct: bool = database::check_password(
                    &state.db,
                    username.as_str(),
                    old_password_hash.as_str(),
                )
                .unwrap();
                if !old_password_hash_correct && !done {
                    send_result_packet(socket.clone(), "err_incorrect_password".to_string()).await;
                    done = true;
                }
                //return the message type variant
                if !done {
                    result = MessageTypes::ChangePassword(
                        username,
                        old_password_hash,
                        new_password_hash,
                        salt,
                    );
                }
            }
            result
        }
        _ => MessageTypes::Invalid,
    };
    ret
}

async fn handle_socket(socket: WebSocket, state: AppState::AppState) {
    let (sender, recievr) = socket.split();
    let socket_state = AppState::SocketState::new(recievr, sender);
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
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    };
    state.remove_socket(id).await;
}
