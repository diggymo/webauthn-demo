use core::str;
use std::sync::Arc;

use axum::{
    extract::State, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}, Json, Router
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use tracing_subscriber::EnvFilter;


#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Register {
    #[serde(rename = "type")]
    _type: String,
    cross_origin: bool,
    origin: String,
    challenge: String,

    // 謎のデコード"CBOR"が出てきたためスキップ
    // attestation_object 
}


enum AppError {
    InvalidPayloadError
}

// Tell axum how `AppError` should be converted into a response.
//
// This is also a convenient place to log errors.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // How we want errors responses to be serialized
        #[derive(Serialize)]
        struct ErrorResponse {
            message: String,
        }

        let (status, message) = match self {
            AppError::InvalidPayloadError => {
                (StatusCode::BAD_REQUEST, ErrorResponse{message: "payload is invalid.".into()})
            }
        };

        (status, axum::Json(message)).into_response()
    }
}

#[derive(Debug)]
struct Challenge {
    expired_at: NaiveDateTime,
    challenge: String
}

#[derive(Debug)]
struct AppState {
    challenges: Vec<Challenge>
}


const PORT: i16 = 3000;

#[tokio::main]
async fn main() {

    tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".into())).init();

    info!(port=PORT, "initializing...");
    let shared_state = Arc::new(AppState { challenges: vec![] });
    
    // build our application with a single route
    let app = Router::new()
    .route("/", get(|| async { "Hello, World!" }))
    .route("/register", post(register))
    .with_state(shared_state);


    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}",PORT)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}


const ORIGIN: &str = "localhost:3000";

#[tracing::instrument]
async fn register(State(state): State<Arc<AppState>>,Json(payload): Json<Register>) -> Result<(),AppError> {

    if payload._type != "webauthn.create" {
        error!(challenge=payload.challenge, "invalid type: {}", payload._type);
        return Err(AppError::InvalidPayloadError);
    }

    if payload.origin != ORIGIN {
        error!(challenge=payload.challenge, "invalid origin: {}", payload.origin);
        return Err(AppError::InvalidPayloadError);
    }

    let is_valid_challenge = state.challenges.iter().any(|challenge| {
        // check is not expired
        challenge.expired_at > chrono::Utc::now().naive_utc() && payload.challenge == challenge.challenge
    });
    if !is_valid_challenge {
        error!(challenge=payload.challenge, "expired or not exist challenge: {}", payload.challenge);
        return Err(AppError::InvalidPayloadError);
    }

    return Ok(());
}