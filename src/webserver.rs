use std::net::SocketAddr;
use axum::extract::State;
use axum::Router;
use axum::routing::get;
use axum_extra::response::{Css, Html, JavaScript};
use tracing::info;
use crate::appstate::AppState;
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