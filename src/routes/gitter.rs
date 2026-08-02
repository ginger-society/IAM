//! SSH user-certificate generation — pure Rust, no ssh-keygen binary.
//!
//! Three endpoints, one per auth level:
//!   POST /ssh-cert/user-land   → Claims      (10-hour TTL)
//!   POST /ssh-cert/api-land    → APIClaims   (20-minute TTL)
//!   POST /ssh-cert/isc-land    → ISCClaims   (365-day TTL)
//!
//! Each endpoint:
//!   1. Generates a fresh ed25519 user keypair (ephemeral).
//!   2. Reads the CA private key from /etc/ssh-ca/ca_key (PEM-encoded ed25519).
//!   3. Signs a certificate for principal = claims.sub, with the appropriate TTL.
//!   4. Returns { private_key_pem, certificate_pem } so the caller can write
//!      ~/.ssh/id_ed25519 + ~/.ssh/id_ed25519-cert.pub.
//!
//! Errors use the shared `ApiError` JSON shape ({ error, message }) instead of
//! a bare `rocket::http::Status`, so callers get a descriptive body instead of
//! an empty 500, and the real cause is preserved in the server-side log line
//! instead of being discarded. See the dbschema/services router for the
//! canonical definition of `ApiError` — if this crate already has a shared
//! `crate::errors::ApiError`, prefer `use crate::errors::ApiError;` here
//! instead of the local copy below.

use chrono::Utc;
use rand::Rng;
use rand::distributions::Alphanumeric;
use rocket::http::{ContentType, Status};
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{post, Request};
use rocket_okapi::openapi;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;

use ginger_shared_rs::rocket_utils::{APIClaims, Claims, ISCClaims};

use ssh_key::{
    PrivateKey, PublicKey,
    certificate::{Builder as CertBuilder, CertType},
    Algorithm,
    LineEnding,
};

use crate::routes::identity::ApiError;


// ── response ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshCertResponse {
    /// PEM-encoded ed25519 private key (write to ~/.ssh/id_ed25519)
    pub private_key_pem: String,
    /// OpenSSH public key line (write to ~/.ssh/id_ed25519.pub)
    pub public_key: String,
    /// OpenSSH certificate line (write to ~/.ssh/id_ed25519-cert.pub)
    pub certificate: String,
    /// Human-readable validity window
    pub valid_for: String,
    /// Principal embedded in the cert
    pub principal: String,
}

// ── helpers ───────────────────────────────────────────────────────────────────

const CA_KEY_PATH: &str = "/etc/ssh-ca/ca_key";

/// Load the CA signing key from the well-known mount path.
fn load_ca_key() -> Result<PrivateKey, ApiError> {
    let pem = fs::read_to_string(CA_KEY_PATH).map_err(|e| {
        ApiError::internal(
            &format!("load_ca_key: reading CA key file at '{}'", CA_KEY_PATH),
            e,
        )
    })?;
    PrivateKey::from_openssh(&pem)
        .map_err(|e| ApiError::internal("load_ca_key: parsing CA key PEM", e))
}

fn issue_cert(principal: &str, ttl_seconds: u64) -> Result<SshCertResponse, ApiError> {
    // 1. Generate an ephemeral user keypair
    let user_key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
        .map_err(|e| {
            ApiError::internal(
                &format!("issue_cert: generating ephemeral keypair for principal '{}'", principal),
                e,
            )
        })?;

    let user_pub: PublicKey = user_key.public_key().clone();

    // 2. Load the CA key
    let ca_key = load_ca_key()?;

    // 3. Build and sign the certificate
    let now = Utc::now().timestamp() as u64;
    let valid_after = now.saturating_sub(10); // small clock-skew buffer
    let valid_before = now + ttl_seconds;

    let serial: u64 = rand::thread_rng().gen();
    let key_id = format!(
        "{}-ephemeral-{}",
        principal,
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
    );

    let mut rng = rand::thread_rng();

    let mut builder = CertBuilder::new_with_random_nonce(
        &mut rng,
        user_pub.clone(),
        valid_after,
        valid_before,
    )
    .map_err(|e| {
        ApiError::internal(
            &format!("issue_cert: CertBuilder::new_with_random_nonce for principal '{}'", principal),
            e,
        )
    })?;

    builder.serial(serial); // serial() returns &mut Builder directly, no Result

    builder
        .cert_type(CertType::User)
        .map_err(|e| ApiError::internal("issue_cert: setting cert_type", e))?
        .key_id(key_id)
        .map_err(|e| ApiError::internal("issue_cert: setting key_id", e))?
        .valid_principal(principal)
        .map_err(|e| {
            ApiError::internal(
                &format!("issue_cert: setting valid_principal '{}'", principal),
                e,
            )
        })?
        .extension("permit-pty", "")
        .map_err(|e| ApiError::internal("issue_cert: adding permit-pty extension", e))?
        .extension("permit-port-forwarding", "")
        .map_err(|e| ApiError::internal("issue_cert: adding permit-port-forwarding extension", e))?
        .extension("permit-agent-forwarding", "")
        .map_err(|e| ApiError::internal("issue_cert: adding permit-agent-forwarding extension", e))?
        .extension("permit-user-rc", "")
        .map_err(|e| ApiError::internal("issue_cert: adding permit-user-rc extension", e))?;

    let cert = builder.sign(&ca_key).map_err(|e| {
        ApiError::internal(
            &format!("issue_cert: signing certificate for principal '{}'", principal),
            e,
        )
    })?;

    // 4. Serialise
    let private_key_pem = user_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| ApiError::internal("issue_cert: serializing private key to OpenSSH PEM", e))?
        .to_string();

    let public_key = user_pub
        .to_openssh()
        .map_err(|e| ApiError::internal("issue_cert: serializing public key to OpenSSH format", e))?;

    let certificate = cert
        .to_openssh()
        .map_err(|e| ApiError::internal("issue_cert: serializing certificate to OpenSSH format", e))?;

    let minutes = ttl_seconds / 60;
    let valid_for = if minutes >= 60 * 24 {
        format!("{} day(s)", minutes / (60 * 24))
    } else if minutes >= 60 {
        format!("{} hour(s)", minutes / 60)
    } else {
        format!("{} minute(s)", minutes)
    };

    Ok(SshCertResponse {
        private_key_pem,
        public_key,
        certificate,
        valid_for,
        principal: principal.to_string(),
    })
}

// ── endpoints ─────────────────────────────────────────────────────────────────

/// Issue an SSH user certificate for an authenticated **user** (10-hour TTL).
#[openapi()]
#[post("/ssh-cert/user-land")]
pub fn ssh_cert_user_land(claims: Claims) -> Result<Json<SshCertResponse>, ApiError> {
    let principal: String = claims.sub;
    let ttl = 10 * 60 * 60; // 10 hours
    let resp = issue_cert(&principal, ttl)?;
    println!(
        "[ssh-cert] user-land cert issued for '{}' (valid_for={})",
        principal, resp.valid_for
    );
    Ok(Json(resp))
}

/// Issue an SSH user certificate for an **API token** caller (20-minute TTL).
#[openapi()]
#[post("/ssh-cert/api-land")]
pub fn ssh_cert_api_land(claims: APIClaims) -> Result<Json<SshCertResponse>, ApiError> {
    let principal = claims.sub;
    let ttl = 20 * 60; // 20 minutes
    let resp = issue_cert(&principal, ttl)?;
    println!(
        "[ssh-cert] api-land cert issued for '{}' (valid_for={})",
        principal, resp.valid_for
    );
    Ok(Json(resp))
}

/// Issue an SSH user certificate for an **ISC** service caller (365-day TTL).
#[openapi()]
#[post("/ssh-cert/isc-land")]
pub fn ssh_cert_isc_land(claims: ISCClaims) -> Result<Json<SshCertResponse>, ApiError> {
    let principal = claims.sub;
    let ttl = 365 * 24 * 60 * 60; // 365 days
    let resp = issue_cert(&principal, ttl)?;
    println!(
        "[ssh-cert] isc-land cert issued for '{}' (valid_for={})",
        principal, resp.valid_for
    );
    Ok(Json(resp))
}