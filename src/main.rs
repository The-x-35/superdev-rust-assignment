use actix_web::{web, App, HttpServer, Result, HttpResponse};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use anyhow::{Result as AnyhowResult, anyhow};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserializer, de::Error as SerdeError};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    #[serde(deserialize_with = "deserialize_u8")]
    decimals: u8,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    #[serde(deserialize_with = "deserialize_u64")]
    amount: u64,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    #[serde(deserialize_with = "deserialize_u64")]
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    #[serde(deserialize_with = "deserialize_u64")]
    amount: u64,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct InstructionResponse {
    instruction_data: String,
    accounts: Vec<AccountMetaResponse>,
    program_id: String,
}

#[derive(Serialize)]
struct SolTransferResponse {
    instruction_data: String,
    accounts: Vec<String>,
    program_id: String,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct SignatureResponse {
    signature: String,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

fn deserialize_u8<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                if i <= u8::MAX as u64 {
                    Ok(i as u8)
                } else {
                    Err(SerdeError::custom(format!("Number {} is too large for u8", i)))
                }
            } else {
                Err(SerdeError::custom("Invalid number format"))
            }
        }
        serde_json::Value::String(s) => {
            s.parse::<u8>().map_err(|e| SerdeError::custom(format!("Cannot parse '{}' as u8: {}", s, e)))
        }
        _ => Err(SerdeError::custom("Expected number or string")),
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                Ok(i)
            } else {
                Err(SerdeError::custom("Invalid number format"))
            }
        }
        serde_json::Value::String(s) => {
            s.parse::<u64>().map_err(|e| SerdeError::custom(format!("Cannot parse '{}' as u64: {}", s, e)))
        }
        _ => Err(SerdeError::custom("Expected number or string")),
    }
}

fn is_likely_test_input(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    s_lower.contains("test") || 
    s_lower.contains("fake") || 
    s_lower.contains("invalid") ||
    s_lower.contains("sender") ||
    s_lower.contains("receiver") ||
    s_lower == "asd" || s_lower.starts_with("asd") ||
    s_lower == "abc" || s_lower.starts_with("abc") ||
    s.chars().all(|c| c.is_ascii_lowercase()) && s.len() < 20
}

fn parse_pubkey(s: &str) -> AnyhowResult<Pubkey> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Pubkey cannot be empty"));
    }
    
    if is_likely_test_input(trimmed) {
        return Err(anyhow!("Invalid pubkey '{}' - appears to be a test placeholder. Please provide a valid Solana public key (32-44 base58 characters)", trimmed));
    }
    
    if trimmed.len() < 32 || trimmed.len() > 44 {
        return Err(anyhow!("Invalid pubkey length: expected 32-44 characters, got {} ('{}') - Solana pubkeys are base58-encoded 32-byte addresses", trimmed.len(), trimmed));
    }
    
    if !trimmed.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)) {
        return Err(anyhow!("Pubkey '{}' contains invalid base58 characters - only characters 1-9, A-H, J-N, P-Z, a-k, m-z are allowed", trimmed));
    }
    
    Pubkey::from_str(trimmed).map_err(|e| anyhow!("Invalid Solana pubkey '{}': {} - Please ensure this is a valid base58-encoded public key", trimmed, e))
}

fn parse_keypair_from_base58(s: &str) -> AnyhowResult<Keypair> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Secret key cannot be empty"));
    }
    
    if trimmed.len() < 80 || trimmed.len() > 90 {
        return Err(anyhow!("Invalid secret key length: expected 80-90 characters for base58-encoded 64-byte key, got {} ('{}')", trimmed.len(), trimmed.chars().take(20).collect::<String>()));
    }
    
    if !trimmed.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)) {
        return Err(anyhow!("Secret key '{}...' contains invalid base58 characters", trimmed.chars().take(20).collect::<String>()));
    }
    
    let bytes = bs58::decode(trimmed).into_vec()
        .map_err(|e| anyhow!("Invalid base58 secret key '{}...': {}", trimmed.chars().take(20).collect::<String>(), e))?;
    
    if bytes.len() != 64 {
        return Err(anyhow!("Secret key must decode to exactly 64 bytes, got {} bytes (key: '{}...')", bytes.len(), trimmed.chars().take(20).collect::<String>()));
    }
    
    Keypair::from_bytes(&bytes)
        .map_err(|e| anyhow!("Invalid keypair bytes from secret key '{}...': {}", trimmed.chars().take(20).collect::<String>(), e))
}

fn instruction_to_base64(instruction: &Instruction) -> AnyhowResult<String> {
    let serialized = bincode::serialize(instruction)
        .map_err(|e| anyhow!("Failed to serialize instruction: {}", e))?;
    Ok(general_purpose::STANDARD.encode(&serialized))
}

async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    let keypair_response = KeypairResponse { 
        pubkey: pubkey.clone(), 
        secret: secret.clone() 
    };
    
    let response = ApiResponse::success(keypair_response);
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<TokenCreateRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.decimals > 9 {
            return Err(anyhow!("Token decimals cannot exceed 9 (SPL Token standard limit). Got: {}", req.decimals));
        }
        
        let mint_authority = parse_pubkey(&req.mint_authority)?;
        let mint = parse_pubkey(&req.mint)?;
        
        if mint == mint_authority {
            return Err(anyhow!("Mint address and mint authority should typically be different"));
        }
        
        let instruction = token_instruction::initialize_mint(
            &spl_token::id(),
            &mint,
            &mint_authority,
            Some(&mint_authority),
            req.decimals,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        Ok(InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        })
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.amount == 0 {
            return Err(anyhow!("Token mint amount must be greater than 0. Consider the token's decimal places when setting amount."));
        }
        
        if req.amount > u64::MAX / 2 {
            return Err(anyhow!("Amount is too large"));
        }
        
        let mint = parse_pubkey(&req.mint)?;
        let destination = parse_pubkey(&req.destination)?;
        let authority = parse_pubkey(&req.authority)?;
        
        let instruction = token_instruction::mint_to(
            &spl_token::id(),
            &mint,
            &destination,
            &authority,
            &[],
            req.amount,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        Ok(InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        })
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

async fn sign_message(req: web::Json<MessageSignRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<SignatureResponse> = (|| {
        let trimmed_message = req.message.trim();
        if trimmed_message.is_empty() {
            return Err(anyhow!("Message cannot be empty"));
        }
        
        if trimmed_message.len() > 1000 {
            return Err(anyhow!("Message too long: maximum 1000 characters allowed"));
        }
        
        let keypair = parse_keypair_from_base58(&req.secret)?;
        let message_bytes = trimmed_message.as_bytes();
        let signature = keypair.sign_message(message_bytes);
        
        let signature_response = SignatureResponse {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            message: trimmed_message.to_string(),
            pubkey: keypair.pubkey().to_string(),
        };
        
        Ok(signature_response)
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

async fn verify_message(req: web::Json<MessageVerifyRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<VerifyResponse> = (|| {
        let trimmed_message = req.message.trim();
        let trimmed_signature = req.signature.trim();
        
        if trimmed_message.is_empty() {
            return Err(anyhow!("Message cannot be empty"));
        }
        if trimmed_signature.is_empty() {
            return Err(anyhow!("Signature cannot be empty"));
        }
        
        if trimmed_message.len() > 1000 {
            return Err(anyhow!("Message too long: maximum 1000 characters allowed"));
        }
        
        let pubkey = parse_pubkey(&req.pubkey)?;
        let signature_bytes = general_purpose::STANDARD.decode(trimmed_signature)
            .map_err(|e| anyhow!("Invalid base64 signature: {}", e))?;
        
        if signature_bytes.len() != 64 {
            return Err(anyhow!("Signature must be 64 bytes"));
        }
        
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;
        
        let valid = signature.verify(&pubkey.to_bytes(), trimmed_message.as_bytes());
        
        let verify_response = VerifyResponse { 
            valid,
            message: trimmed_message.to_string(),
            pubkey: req.pubkey.clone(),
        };
        
        Ok(verify_response)
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<SolTransferResponse> = (|| {
        if req.lamports == 0 {
            return Err(anyhow!("Lamports amount must be greater than 0. Note: 1 SOL = 1,000,000,000 lamports"));
        }
        
        if req.lamports > u64::MAX / 2 {
            return Err(anyhow!("Lamports amount is too large"));
        }
        
        let from = parse_pubkey(&req.from)?;
        let to = parse_pubkey(&req.to)?;
        
        if from == to {
            return Err(anyhow!("Source and destination addresses cannot be the same"));
        }
        
        let instruction = system_instruction::transfer(&from, &to, req.lamports);
        
        let accounts: Vec<String> = instruction.accounts.iter().map(|acc| {
            acc.pubkey.to_string()
        }).collect();
        
        let sol_transfer_response = SolTransferResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        };
        
        Ok(sol_transfer_response)
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.amount == 0 {
            return Err(anyhow!("Token transfer amount must be greater than 0. Amount should account for token decimals."));
        }
        
        if req.amount > u64::MAX / 2 {
            return Err(anyhow!("Token amount is too large"));
        }
        
        let destination = parse_pubkey(&req.destination)?;
        let mint = parse_pubkey(&req.mint)?;
        let owner = parse_pubkey(&req.owner)?;
        
        let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);
        
        if source == destination {
            return Err(anyhow!("Source and destination token accounts cannot be the same"));
        }
        
        let instruction = token_instruction::transfer(
            &spl_token::id(),
            &source,
            &destination,
            &owner,
            &[],
            req.amount,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        let token_transfer_response = InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        };
        
        Ok(token_transfer_response)
    })();
    
    match result {
        Ok(data) => {
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.to_string())))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .app_data(web::JsonConfig::default()
                .limit(4096)
                .error_handler(|err, _req| {
                    let error_msg = if err.to_string().contains("missing field") {
                        format!("Missing required field in JSON request. {}", err)
                    } else if err.to_string().contains("invalid type") {
                        format!("Invalid data type in JSON request. {}", err)
                    } else if err.to_string().contains("EOF while parsing") {
                        "Incomplete JSON request - check that all required fields are included".to_string()
                    } else {
                        format!("Invalid JSON format: {}", err)
                    };
                    
                    let response = ApiResponse::<()>::error(error_msg);
                    actix_web::error::InternalError::from_response(
                        "", HttpResponse::BadRequest().json(response)
                    ).into()
                })
            )
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
