use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct RequestPasswordRequest {
    pub email_id: String,
    pub app_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RegisterRequestValue {
    pub email: String,
    pub hashed_password: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateGroupRequest {
    pub id: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub mobile_number: Option<String>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub app_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ValidateTokenRequest {
    pub access_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ChangePasswordRequest {
    pub email: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateApiTokenRequest {
    pub days_to_expire: i64,
    pub name: String,
    pub group_identifier: String, // Changed to i64 for consistency with your schema
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateSessionTokenRequest {
    pub api_token: String,
    pub days_to_expire: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AcceptInviteRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct InviteRequest {
    pub first_name: String,
    pub last_name: String,
    pub middle_name: Option<String>,
    pub email_id: String,
    pub is_root: bool,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct CreateOrUpdateAppRequest {
    pub client_id: String,
    pub name: Option<String>,
    pub logo_url: Option<String>,
    pub disabled: Option<bool>,
    pub app_url_dev: Option<String>,
    pub app_url_stage: Option<String>,
    pub app_url_prod: Option<String>,
    pub group_id: Option<i64>,
    pub tnc_link: Option<String>,
    pub allow_registration: Option<bool>,
    pub description: Option<String>,
    pub auth_redirection_path: Option<String>,
    pub web_interface: Option<bool>,
}


#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DockerAccess {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
    pub actions: Vec<String>,
}


