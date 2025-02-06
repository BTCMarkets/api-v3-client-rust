use base64::{engine::general_purpose::STANDARD, Engine};
use dotenv::dotenv;
use reqwest::{Client, Method};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BTCMarketsError {
    #[error(
        "BTC Markets API key not found in environment variables. Please set BTCMARKETS_API_KEY"
    )]
    MissingApiKey,

    #[error("BTC Markets private key not found in environment variables. Please set BTCMARKETS_PRIVATE_KEY")]
    MissingPrivateKey,

    #[error(transparent)]
    EnvVarError(#[from] env::VarError),

    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Invalid base64 encoding: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Serdejson error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Order {
    #[serde(rename = "marketId")]
    pub market_id: String,
    pub price: String,
    pub amount: String,
    #[serde(rename = "type")]
    pub order_type: String,
    pub side: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Withdrawal {
    #[serde(rename = "assetName")]
    pub asset_name: String,
    pub amount: String,
    #[serde(rename = "toAddress")]
    pub to_address: String,
}

#[derive(Debug, Deserialize)]
pub struct OrderResponse {
    #[serde(rename = "orderId")]
    pub id: String,
    #[serde(rename = "marketId")]
    pub market_id: String,
    pub side: String,
    #[serde(rename = "type")]
    pub order_type: String,
    #[serde(rename = "creationTime")]
    pub creation_time: String,
    pub price: String,
    pub amount: String,
    #[serde(rename = "openAmount")]
    pub open_amount: String,
    pub status: String,
    #[serde(rename = "postOnly")]
    pub post_only: bool,
}

#[derive(Debug, Deserialize)]
pub struct WithdrawalResponse {
    pub id: String,
    pub status: String,
    // Add other fields as needed
}

#[derive(Debug, Deserialize)]
pub struct APIError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct PlaceOrderResponse {
    #[serde(rename = "orderId")]
    pub order_id: String,
    #[serde(rename = "marketId")]
    pub market_id: String,
    pub status: String,
}

pub struct BTCMarketsClient {
    base_url: String,
    api_key: String,
    private_key: Vec<u8>,
    client: Client,
}

impl BTCMarketsClient {
    /// Creates a new BTCMarkets client
    ///
    /// # Arguments
    /// * `api_key` - Your BTCMarkets API key
    /// * `private_key` - Your BTCMarkets private key (base64 encoded)
    ///
    /// # Returns
    /// A Result containing either a new BTCMarketsClient or a BTCMarketsError
    pub fn new(api_key: String, private_key: String) -> Result<Self, BTCMarketsError> {
        Ok(Self {
            base_url: "https://api.btcmarkets.net".to_string(),
            api_key,
            private_key: STANDARD.decode(&private_key)?,
            client: Client::new(),
        })
    }

    /// Gets all orders for the account
    pub async fn get_orders(&self) -> Result<Vec<OrderResponse>, BTCMarketsError> {
        let endpoint = "/v3/orders";
        let response = self
            .make_request(Method::GET, endpoint, None::<&()>)
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            // Try to parse as an API error
            if let Ok(api_error) = serde_json::from_str::<APIError>(&body) {
                return Err(BTCMarketsError::AuthError(format!(
                    "{}: {}",
                    api_error.code, api_error.message
                )));
            }
        }

        // Only try to parse as Vec<OrderResponse> if it's a success response
        match serde_json::from_str(&body) {
            Ok(orders) => Ok(orders),
            Err(e) => {
                println!("Parse error: {}", e);
                println!("Failed to parse body: {}", body);
                Err(BTCMarketsError::SerdeJsonError(e))
            }
        }
    }
    /// Places a new order
    pub async fn place_order(&self, order: &Order) -> Result<PlaceOrderResponse, BTCMarketsError> {
        let endpoint = "/v3/orders";
        let response = self
            .make_request(Method::POST, endpoint, Some(order))
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            // Try to parse as an API error
            if let Ok(api_error) = serde_json::from_str::<APIError>(&body) {
                return Err(BTCMarketsError::AuthError(format!(
                    "{}: {}",
                    api_error.code, api_error.message
                )));
            }
        }

        // If it's a success response, parse as PlaceOrderResponse
        match serde_json::from_str(&body) {
            Ok(order_response) => Ok(order_response),
            Err(e) => Err(BTCMarketsError::SerdeJsonError(e)),
        }
    }

    /// Creates a new withdrawal request
    pub async fn create_withdrawal(
        &self,
        withdrawal: &Withdrawal,
    ) -> Result<WithdrawalResponse, BTCMarketsError> {
        let endpoint = "/v3/withdrawals";
        let response = self
            .make_request(Method::POST, endpoint, Some(withdrawal))
            .await?;
        Ok(response.json().await?)
    }

    /// Makes a signed HTTP request to the BTCMarkets API
    async fn make_request<T: Serialize>(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, BTCMarketsError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();

        let body_str = body
            .map(|b| serde_json::to_string(b).unwrap())
            .unwrap_or_default();
        let signature = self.sign_request(&method, endpoint, &timestamp, &body_str);

        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, endpoint))
            .header("Accept", "application/json")
            .header("Accept-Charset", "UTF-8")
            .header("Content-Type", "application/json")
            .header("BM-AUTH-APIKEY", &self.api_key)
            .header("BM-AUTH-TIMESTAMP", &timestamp)
            .header("BM-AUTH-SIGNATURE", signature);

        if !body_str.is_empty() {
            request = request.body(body_str);
        }

        Ok(request.send().await?)
    }

    /// Signs a request using HMAC-SHA512
    fn sign_request(&self, method: &Method, endpoint: &str, timestamp: &str, body: &str) -> String {
        let message = format!("{}{}{}{}", method.as_str(), endpoint, timestamp, body);
        let key = hmac::Key::new(hmac::HMAC_SHA512, &self.private_key);
        let signature = hmac::sign(&key, message.as_bytes());
        STANDARD.encode(signature.as_ref())
    }
}

fn get_credentials() -> Result<(String, String), BTCMarketsError> {
    // Optional: Load .env file if it exists
    dotenv().ok();

    // Get API key
    let api_key = env::var("BTCMARKETS_API_KEY").map_err(|_| BTCMarketsError::MissingApiKey)?;

    // Get private key
    let private_key =
        env::var("BTCMARKETS_PRIVATE_KEY").map_err(|_| BTCMarketsError::MissingPrivateKey)?;

    Ok((api_key, private_key))
}

async fn run() -> Result<(), BTCMarketsError> {
    let (api_key, private_key) = get_credentials()?;
    let client = BTCMarketsClient::new(api_key, private_key)?;

    // Get all orders
    let orders = client.get_orders().await?;
    println!("Current orders: {:?}", orders);

    // Place a new order
    let new_order = Order {
        market_id: "XRP-AUD".to_string(),
        price: "1.00".to_string(),
        amount: "0.01".to_string(),
        order_type: "Limit".to_string(),
        side: "Bid".to_string(),
    };

    let order_result = client.place_order(&new_order).await?;
    println!("Order placed: {:?}", order_result);

    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#?}: {e}");
            ExitCode::FAILURE
        }
    }
}
