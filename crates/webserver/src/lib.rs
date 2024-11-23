/// Imports for the web server module
use database::Password;
use file_helpers::*;
use futures::{SinkExt, StreamExt};
use local_ip_address::list_afinet_netifas;
use rcgen::{date_time_ymd, CertificateParams, DnType, KeyPair};
use std::io::Read;
use std::net::SocketAddr;
use std::string::FromUtf8Error;
use std::time::Duration;
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;
use tracing::info;
use warp::filters::ws::{Message, WebSocket};
use warp::{reply, Filter as _};

/// Message types for the binary communication protocol
/// Each variant represents a different type of message that can be sent/received
#[derive(Debug)]
pub enum MessageTypes {
    /// Invalid or malformed message
    Invalid,
    /// Authentication request (username, password_hash)
    Auth(String, String),
    /// Request for user's salt value for password hashing (username)
    RequestSalt(String),
    /// Account creation request (username, password_hash, salt)
    CreateAccount(String, String, String),
    /// Password change request (username, old_hash, new_hash, new_salt)
    ChangePassword(String, String, String, String),
}

/// Initializes and starts the HTTPS web server
/// Takes application state as parameter
pub async fn start_web_server(state: app_state::AppState) {
    let (interface_proper, interface_pretty, port) = get_config_values(state.clone()).await;
    info!("Starting web server on {}:{}", interface_pretty, port);
    check_certs();
    let address: SocketAddr = parse_interface_address(&interface_proper, port);
    start_server(state, address).await;
}

/// Checks if required SSL certificate files exist, regenerates them if missing
fn check_certs() {
    if !check_file_exists("certs/cert.pem")
        || !check_file_exists("certs/key.pem")
        || !check_file_exists("certs/cert.der")
        || !check_file_exists("certs/key.der")
    {
        info!("one of the cert files was missing, so I need to regenerate all of them");
        let _ = generate_cert_and_key();
    }
}

/// Parses interface address string into SocketAddr
/// Provides helpful error message if parsing fails
fn parse_interface_address(interface: &str, port: u16) -> SocketAddr {
    SocketAddr::new(
        interface.parse().expect("config.interface is an invalid IP address\nif you don't care where requests come from, use 0.0.0.0\nto only accept requests from the local network, find your gateway IP and configure interface to match that.\nin a multi-network situation, choose the IP of the network adapter within the network you want to accept requests from, only requests from there would be accepted"),
        port,
    )
}

/// Generates self-signed SSL certificate and private key files
/// Creates both PEM and DER format files
fn generate_cert_and_key() -> Result<(), Box<dyn std::error::Error>> {
    let subject_alts = get_local_addresses();
    let mut params: CertificateParams = Default::default();
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
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
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to self sign certificate");

    if !check_file_exists("/certs") {
        std::fs::create_dir("/certs").expect("Failed to create /certs directory");
    }

    let pem_serial = cert.pem();
    write_to_file("certs/cert.pem", &pem_serial).expect("Failed to write cert.pem");
    let der = cert.der();
    let der_bytes = der.bytes();
    write_bytes_to_file(der_bytes, "certs/cert.der").expect("Failed to write cert.der");
    let key_serial = key_pair.serialize_pem();
    write_to_file("certs/key.pem", &key_serial).expect("Failed to write key.pem");
    let key_der = key_pair.serialize_der();
    std::fs::write("certs/key.der", key_der).expect("Failed to write key.der");
    Ok(())
}

/// Gets list of all local IP addresses for certificate generation
fn get_local_addresses() -> Vec<String> {
    let mut addresses: Vec<String> = list_afinet_netifas()
        .expect("Failed to get network interfaces")
        .into_iter()
        .map(|(_, ip)| ip.to_string())
        .collect();

    addresses.push("localhost".to_string());
    addresses.push("::1".to_string());

    addresses
}

/// Gets interface and port configuration values from application state
async fn get_config_values(state: app_state::AppState) -> (String, String, u16) {
    let config = state.config.lock().await;
    let interface_proper = config.interface.clone();
    let interface_pretty = interface_proper.replace("0.0.0.0", "*");
    let port = config.port.clone();
    drop(config);
    (interface_proper, interface_pretty, port)
}

/// Starts the HTTPS server with WebSocket support
/// Serves static files and handles WebSocket connections
async fn start_server(state: app_state::AppState, address: SocketAddr) {
    // Load static file contents
    const JS_CONTENT: &str = include_str!("../html_src/index.js");
    const CSS_CONTENT: &str = include_str!("../html_src/style.css");
    const HTML_CONTENT: &str = include_str!("../html_src/index.html");
    const CRYPTO_CONTENT: &str = include_str!("../html_src/crypto.min.js");
    const JQUERY_CONTENT: &str = include_str!("../html_src/jquery.min.js");
    const SECURITY_KEY_SVG_CONTENT: &str = include_str!("../html_src/security_key.svg");

    check_certs();

    let cert = "certs/cert.pem";
    let key = "certs/key.pem";

    // Define routes for static files and WebSocket endpoint
    let routes = warp::path::end()
        .map(|| warp::reply::html(HTML_CONTENT))
        .or(warp::path("index.js").map(|| serve_javascript(JS_CONTENT)))
        .or(warp::path("style.css").map(|| serve_css(CSS_CONTENT)))
        .or(warp::path("crypto.js").map(|| serve_javascript(CRYPTO_CONTENT)))
        .or(warp::path("jquery.js").map(|| serve_javascript(JQUERY_CONTENT)))
        .or(warp::path("security_key.svg").map(|| serve_svg(SECURITY_KEY_SVG_CONTENT)))
        .or(warp::path("ws")
            .and(warp::ws())
            .and(warp::any().map(move || state.clone()))
            .map(|ws: warp::ws::Ws, state: app_state::AppState| {
                ws.on_upgrade(move |socket| handle_socket(socket, state))
            }));

    // Start HTTPS server
    warp::serve(routes)
        .tls()
        .cert_path(cert)
        .key_path(key)
        .run(address)
        .await;
}

/// Serves JavaScript files with correct MIME type
fn serve_javascript(js_content: &'static str) -> impl warp::Reply {
    reply::with_header(
        reply::html(js_content),
        "Content-Type",
        "application/javascript",
    )
}

/// Serves SVG files with correct MIME type
fn serve_svg(svg_content: &'static str) -> impl warp::Reply {
    reply::with_header(reply::html(svg_content), "Content-Type", "image/svg+xml")
}

/// Serves CSS files with correct MIME type
fn serve_css(css_content: &'static str) -> impl warp::Reply {
    reply::with_header(reply::html(css_content), "Content-Type", "text/css")
}

/// Handles broadcast messages from server to client
/// Sends messages through WebSocket and handles disconnections
async fn handle_send_task(
    mut global_tx: Receiver<String>,
    socket: app_state::SocketState,
    id: usize,
    _state: app_state::AppState,
) {
    while let Ok(val) = global_tx.recv().await {
        let message = Message::text(val);
        let mut sender = socket.tx.lock().await;
        let send_result = sender.send(message).await;
        drop(sender);

        if let Err(_) = send_result {
            info!(
                "Socket ID: {} has disconnected since last broadcast, terminating listener loop",
                id
            );
            break;
        }
    }
}

/// Decodes binary buffer into UTF-8 string
fn decode_string_from_buffer(buffer: &[u8]) -> Result<String, FromUtf8Error> {
    String::from_utf8(buffer[0..].to_vec())
}

/// Sends binary message through WebSocket
async fn send_binary_message_to_tx(socket: &app_state::SocketState, message: &[u8]) {
    let _ = socket
        .tx
        .lock()
        .await
        .send(Message::binary(message.to_vec()))
        .await;
}

/// Sends formatted result packet through WebSocket
/// Packet format: [0x5F, 0x10, opcode(2), msg_len(8), msg_bytes]
async fn send_result_packet(socket: app_state::SocketState, msg: String) {
    let mut tx = socket.tx.lock().await;
    let mut buffer: Vec<u8> = vec![0x5F, 0x10];
    let opcode = u16::to_be_bytes(0x02u16);
    let msg_len = u64::to_be_bytes(msg.len() as u64);
    let msg_bytes = &msg.as_bytes();
    buffer.extend_from_slice(&opcode);
    buffer.extend_from_slice(&msg_len);
    buffer.extend_from_slice(&msg_bytes);

    let _ = tx.send(Message::binary(buffer)).await;
}

/// Handles incoming messages from client
/// Processes binary protocol packets and manages authentication state
async fn handle_recv_task(
    _global_tx: Receiver<String>,
    socket: app_state::SocketState,
    id: usize,
    state: app_state::AppState,
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
            Err(_) => continue,
        };
        drop(rx);

        if message.is_text() {
            if message.to_str().unwrap_or("").is_empty() {
                continue;
            }
        }

        // Handle binary protocol messages
        if message.is_binary() {
            let message = message.as_bytes();
            // Check magic bytes
            if message[0] != 0x5F || message[1] != 0x10 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                continue;
            }

            let opcode: u16 = u16::from_be_bytes([message[2], message[3]]);
            let message = &message[4..];
            let message: MessageTypes =
                check_message(opcode, message, id, socket.clone(), state.clone()).await;

            match message {
                // Handle authentication
                MessageTypes::Auth(username, password_hash) => {
                    let auth = database::check_password(
                        state.db.clone(),
                        username.as_str(),
                        password_hash.as_str(),
                    )
                    .await
                    .expect("Failed to check password");

                    if auth {
                        send_result_packet(socket.clone(), "authed".to_string()).await;
                        *socket.authenticated.lock().await = true;
                        *socket.username.lock().await = Some(username);
                    } else {
                        send_result_packet(socket.clone(), "Incorrect Password".to_string()).await;
                    }
                }
                // Handle salt request
                MessageTypes::RequestSalt(username) => {
                    let salt = database::get_salt(state.db.clone(), username.as_str())
                        .await
                        .expect("Failed to get salt");

                    let salt = salt.as_bytes();
                    let mut salt_message = vec![0x5F, 0x10];
                    salt_message.extend_from_slice(&1u16.to_be_bytes());
                    salt_message.extend_from_slice(salt);
                    send_binary_message_to_tx(&socket, &salt_message).await;
                }
                // Handle account creation
                MessageTypes::CreateAccount(username, password_hash, salt) => {
                    let password = Password {
                        hash: password_hash,
                        salt,
                        security_key: None,
                    };

                    let success =
                        database::add_credentials(state.db.clone(), username.as_str(), password)
                            .await
                            .is_ok();

                    if success {
                        send_result_packet(socket.clone(), "acct_created".to_string()).await;
                        send_result_packet(socket.clone(), "authed".to_string()).await;
                        *socket.authenticated.lock().await = true;
                        *socket.username.lock().await = Some(username);
                    } else {
                        send_result_packet(socket.clone(), "acct_gen_fail".to_string()).await;
                    }
                }
                // Handle password change
                MessageTypes::ChangePassword(username, old_hash, new_password_hash, salt) => {
                    let key = database::get_security_key(state.db.clone(), &username).await;
                    let password = Password {
                        hash: new_password_hash,
                        salt,
                        security_key: key,
                    };
                    let success =
                        database::change_password(state.db.clone(), &username, &old_hash, password)
                            .await
                            .is_ok();

                    if success {
                        send_result_packet(socket.clone(), "pass_chngd".to_string()).await;
                    } else {
                        send_result_packet(socket.clone(), "pass_chng_fail".to_string()).await;
                    }
                }
                _ => (),
            }
        }
    }
}

/// Processes binary protocol messages based on opcode
/// Binary packet format varies by message type but generally follows:
/// [length fields (8 bytes each)][payload string fields]
async fn check_message(
    opcode: u16,
    message: &[u8],
    _id: usize,
    socket: app_state::SocketState,
    state: app_state::AppState,
) -> MessageTypes {
    match opcode {
        // Request salt for username
        1 => {
            let username = match decode_string_from_buffer(message) {
                Ok(username) => username,
                Err(_) => {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    return MessageTypes::Invalid;
                }
            };

            if !database::user_exists(state.db, username.as_str()).await {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            MessageTypes::RequestSalt(username)
        }
        // Authentication request
        2 => {
            if *socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_already_authenticated".to_string()).await;
                return MessageTypes::Invalid;
            }

            if message.len() < 16 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username_length = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            let password_hash_length = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);

            let message = match decode_string_from_buffer(&message[16..]) {
                Ok(message) => message,
                Err(_) => {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    return MessageTypes::Invalid;
                }
            };

            if message.len() != (username_length + password_hash_length) as usize {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username = message[0..username_length as usize].to_string();
            let password_hash = message[username_length as usize..].to_string();

            if !database::user_exists(state.db, username.as_str()).await {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            MessageTypes::Auth(username, password_hash)
        }
        // Create account request
        3 => {
            if *socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_already_authenticated".to_string()).await;
                return MessageTypes::Invalid;
            }

            if message.len() < 24 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username_length = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            let password_hash_length = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);
            let salt_length = u64::from_be_bytes([
                message[16],
                message[17],
                message[18],
                message[19],
                message[20],
                message[21],
                message[22],
                message[23],
            ]);

            let message = match decode_string_from_buffer(&message[24..]) {
                Ok(message) => message,
                Err(_) => {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    return MessageTypes::Invalid;
                }
            };

            if message.len() < (username_length + password_hash_length + salt_length) as usize {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username = message[0..username_length as usize].to_string();
            let password_hash = message
                [username_length as usize..(username_length + password_hash_length) as usize]
                .to_string();
            let salt = message[(username_length + password_hash_length) as usize..].to_string();

            if database::user_exists(state.db, username.as_str()).await {
                send_result_packet(socket.clone(), "err_username_taken".to_string()).await;
                return MessageTypes::Invalid;
            }

            MessageTypes::CreateAccount(username, password_hash, salt)
        }
        // Change password request
        4 => {
            if !*socket.authenticated.lock().await {
                send_result_packet(socket.clone(), "err_not_authorized".to_string()).await;
                return MessageTypes::Invalid;
            }

            if message.len() < 32 {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username_length = u64::from_be_bytes([
                message[0], message[1], message[2], message[3], message[4], message[5], message[6],
                message[7],
            ]);
            let old_password_hash_length = u64::from_be_bytes([
                message[8],
                message[9],
                message[10],
                message[11],
                message[12],
                message[13],
                message[14],
                message[15],
            ]);
            let new_password_hash_length = u64::from_be_bytes([
                message[16],
                message[17],
                message[18],
                message[19],
                message[20],
                message[21],
                message[22],
                message[23],
            ]);
            let salt_length = u64::from_be_bytes([
                message[24],
                message[25],
                message[26],
                message[27],
                message[28],
                message[29],
                message[30],
                message[31],
            ]);

            let message = match decode_string_from_buffer(&message[32..]) {
                Ok(message) => message,
                Err(_) => {
                    send_result_packet(socket.clone(), "invalid".to_string()).await;
                    return MessageTypes::Invalid;
                }
            };

            if message.len()
                < (username_length
                    + old_password_hash_length
                    + new_password_hash_length
                    + salt_length) as usize
            {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            let username = message[0..username_length as usize].to_string();
            let old_password_hash = message[username_length as usize
                ..username_length as usize + old_password_hash_length as usize]
                .to_string();
            let new_password_hash = message[username_length as usize
                + old_password_hash_length as usize
                ..username_length as usize
                    + old_password_hash_length as usize
                    + new_password_hash_length as usize]
                .to_string();
            let salt = message[username_length as usize
                + old_password_hash_length as usize
                + new_password_hash_length as usize..]
                .to_string();

            if !database::user_exists(state.db.clone(), username.as_str()).await {
                send_result_packet(socket.clone(), "invalid".to_string()).await;
                return MessageTypes::Invalid;
            }

            if !database::check_password(state.db, username.as_str(), old_password_hash.as_str())
                .await
                .unwrap()
            {
                send_result_packet(socket.clone(), "err_incorrect_password".to_string()).await;
                return MessageTypes::Invalid;
            }

            MessageTypes::ChangePassword(username, old_password_hash, new_password_hash, salt)
        }
        _ => MessageTypes::Invalid,
    }
}

/// Handles new WebSocket connections
/// Sets up send/receive tasks and manages connection lifecycle
async fn handle_socket(socket: WebSocket, state: app_state::AppState) {
    let (sender, recievr) = socket.split();
    let socket_state = app_state::SocketState::new(recievr, sender);
    let id: usize = state.add_socket(socket_state.clone()).await;

    let mut send_task = tokio::spawn(handle_send_task(
        state.tx.subscribe(),
        socket_state.clone(),
        id,
        state.clone(),
    ));

    let mut recv_task = tokio::spawn(handle_recv_task(
        state.tx.subscribe(),
        socket_state.clone(),
        id,
        state.clone(),
    ));

    let _ = tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    };

    state.remove_socket(id).await;
}
