use axum::{
    extract::{Query, State},
    response::Json,
    routing::get,
    Router,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct SignRequest {
    hash: String,
}

#[derive(Serialize)]
struct SignResponse {
    hash: String,
    signature: String,
    public_key: String,
}

struct AppState {
    signing_key: SigningKey,
}

async fn sign_handler(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<SignRequest>,
) -> String {
    let state = state.lock().await;
    
    // Decode the hash from hex
    let hash_bytes = match hex::decode(&params.hash) {
        Ok(bytes) => bytes,
        Err(_) => {
            // If decoding fails, return an error response with empty signature
            return format!("{}\nerror: invalid hex\n{}\n",
                params.hash,
                hex::encode(state.signing_key.verifying_key().to_bytes()),
            );
        }
    };
    
    // Sign the hash
    let signature = state.signing_key.sign(&hash_bytes);
    
    // Get public key
    let public_key = state.signing_key.verifying_key();
    
    // Return response
    format!("{}\n{}\n{}\n",
        params.hash.to_lowercase(),
        hex::encode(signature.to_bytes()),
        hex::encode(public_key.to_bytes()),
    )
}

#[tokio::main]
async fn main() {
    // Generate a new signing key
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    
    println!("Server starting...");
    println!("Public Key: {}", hex::encode(signing_key.verifying_key().to_bytes()));
    
    // Create shared state
    let state = Arc::new(Mutex::new(AppState { signing_key }));
    
    // Build the router
    let app = Router::new()
        .route("/sign", get(sign_handler))
        .with_state(state);
    
    // Run the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Listening on http://0.0.0.0:3000");
    println!("Example: http://localhost:3000/sign?hash=abcd1234");
    
    axum::serve(listener, app).await.unwrap();
}
