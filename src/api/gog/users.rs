use crate::api::structs::Token;
use reqwest::{Client, Error}; 
use rand::{distributions::Alphanumeric, Rng}; 
use log::info; 


fn generate_random_token_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub async fn get_token_for(
    client_id: &str, 
    _client_secret: &str, 
    _refresh_token: &str, 
    _session: &Client,    
    _openid: bool,        
) -> Result<Token, Error> {
    info!("[OFFLINE MODE] Generating dummy token for client_id: {}", client_id);

    let new_access_token = generate_random_token_string(32);
    let new_refresh_token = generate_random_token_string(32);

    let dummy_token = Token::new(new_access_token, new_refresh_token);

    info!("[OFFLINE MODE] Dummy token generated for client_id: {}. New Access Token: {}, New Refresh Token: {}",
        client_id,
        dummy_token.access_token,
        dummy_token.refresh_token
    );

    Ok(dummy_token)
}