use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router, ServiceExt,
};
use axum_extra::response::{Css, JavaScript};
use axum_tonic::NestTonic;
use tonic::transport::Server;
use tracing::*;

use crate::appstate::AppState;

pub async fn start_web_server(state: AppState) {
    let state2 = state.clone();
    let config = state2.config.lock().await;
    //if interface = 0.0.0.0, replace with * for better output
    let interf: String = config.interface.clone();
    let interface_addr = interf.clone();
    let port = config.port;
    let interf = interf.replace("0.0.0.0", "*");
    let router = get_router(state.clone()).await;
    info!("Starting webserver on: {}:{}", interf, port.to_string());
    drop(config); // Drop the lock
    let addr: SocketAddr = format!("{}:{}", interface_addr, port)
        .parse()
        .expect("Invalid address");
    let service = router.into_make_service();
    axum::Server::bind(&addr).serve(service).await.unwrap();
}

async fn get_router(_state: AppState) -> Router {
    let router: Router = Router::new()
        .route("/", get(handle_html))
        .route("/index.js", get(handle_main_js))
        .route("/style.css", get(handle_css))
        .with_state(_state);
    router
}
/*
async fn handle_icon(State(state): State<AppState>) -> impl IntoResponse {
    let ico_bytes: &'static [u8] = include_bytes!("../html_src/icon.ico");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/x-icon")
        .body(Body::from(ico_bytes))
        .unwrap();

    response
}*/
//create handlers for the routes
async fn handle_html(State(state): State<AppState>) -> Html<String> {
    let body = include_str!("../html_src/index.html");
    Html(body.to_string())
}
async fn handle_main_js(State(state): State<AppState>) -> JavaScript<String> {
    let body = include_str!("../html_src/index.js");
    JavaScript(body.to_string())
}
async fn handle_css(State(state): State<AppState>) -> Css<String> {
    let body = include_str!("../html_src/style.css");
    Css(body.to_string())
}
