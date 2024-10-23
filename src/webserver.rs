use crate::appstate::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::Response;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_extra::response::{Css, Html, JavaScript};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast::Receiver;
use tokio::sync::Mutex;
use tracing::info;

enum MessageTypes {
    Invalid,
    Auth(String, String, String), //this one expects a username and a hashed password and salt
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
    pub authenticated: bool,
    pub username: Option<String>,
    pub tx: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    pub rx: Arc<Mutex<SplitStream<WebSocket>>>,
}

impl SocketState {
    pub fn new(rx: SplitStream<WebSocket>, tx: SplitSink<WebSocket, Message>) -> Self {
        Self {
            authenticated: false,
            username: None,
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

async fn handle_recv_task(
    global_tx: Receiver<String>,
    socket: SocketState,
    id: usize,
    state: AppState,
) {
    //this function will be used to receive messages from the client and broadcast them to all clients
    let mut reciever = socket.rx.lock().await; //this should be the only place we need the reciever, so there is no issue owning until disconnect.
    while let Some(val) = reciever.next().await {
        match val {
            Ok(message) => {
                //in here, we will expect the first two bytes to be 0x5F10, if not, respond with a message: "Invalid Message", our messages will then have an opcode, which is an 8 bit unsigned integer, followed by the message, messages are a binary format that are similar to how structs in
                //C are represented in memory, this reduces the amount of data that needs to be sent, and allows for more complex messages to be sent
                let message: MessageTypes = match message {
                    Message::Text(text) => continue, //ignore text messages
                    Message::Binary(bin) => {
                        if bin.len() < 4 {
                            //if the message is less than 4 bytes, it is invalid, respond with an error message

                            let mut sender = socket.tx.lock().await;
                            let message = Message::Text("Invalid Message".to_string());
                            let _ = sender.send(message).await;
                            continue;
                        }
                        //check header in first two bytes
                        let header = bin[0] << 8 | bin[1];
                        if header != 0x5F10 {
                            let mut sender = socket.tx.lock().await;
                            let message = Message::Text("Invalid Message".to_string());
                            let _ = sender.send(message).await;
                            continue;
                        }
                        //get opcode and take the rest of the message
                        let opcode = bin[2];
                        let message = &bin[3..];
                        let to_ret: MessageTypes = match opcode {
                            0 => {
                                //this is a message to be broadcasted to all clients
                                let message = String::from_utf8_lossy(message).to_string();
                                let mut global_tx = state.tx.clone();
                                let _ = global_tx.send(message).await;
                                continue;
                            }
                            1 => {
                                //this is a message to be sent to a specific client
                                let message = String::from_utf8_lossy(message).to_string();
                                message
                            }
                            _ => {
                                //this is an invalid opcode, respond with an error message
                                let mut sender = socket.tx.lock().await;
                                let message = Message::Text("Invalid Message".to_string());
                                let _ = sender.send(message).await;
                                continue;
                            }
                        };
                        to_ret
                    }
                    _ => continue, //ignore other message types
                };
            }
            Err(_) => {
                info!(
                    "Socket ID: {} has disconnected, terminating listener loop",
                    id
                );
                break; //break out of the loop if the client is disconnected, no need to keep trying to receive messages
            }
        }
    }
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
