use crate::middlewares::BasicAuth::BasicAuth;
use crate::models::response::{AccessibleApp, DockerTokenResponse, IAMLoginResponse, IsMemberResponse};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use diesel::pg::Pg;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_types::Bool;
use diesel::{insert_into, PgConnection, RunQueryDsl};
use diesel::{prelude::*, update};
use ginger_shared_rs::rocket_models::MessageResponse;
use ginger_shared_rs::rocket_utils::{APIClaims, Claims};
use ginger_shared_rs::rocket_utils::ISCClaims;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use r2d2_redis::redis::Commands;
use r2d2_redis::RedisConnectionManager;
use rand::Rng;
use rocket::http::{ContentType, Status};
use rocket::response::{self, status, Responder};
use rocket::serde::json::Json;
use rocket::{post, Request, State};
use rocket_okapi::openapi;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::io::Cursor;
use NotificationService::apis::configuration::ApiKey as NotificationApiKey;
use NotificationService::apis::default_api::{send_email, SendEmailParams};
use NotificationService::get_configuration as get_notification_service_configuration;

use crate::middlewares::groups::GroupMemberships;
use crate::middlewares::groups_owned::GroupOwnerships;
use crate::models::request::{
    AcceptInviteRequest, CreateOrUpdateAppRequest, InviteRequest, RegisterRequestValue,
};
use crate::models::request::{
    ChangePasswordRequest, CreateApiTokenRequest, CreateGroupRequest, CreateSessionTokenRequest,
    LoginRequest, LogoutRequest, RefreshTokenRequest, RegisterRequest, RequestPasswordRequest,
    ResetPasswordRequest, UpdateProfileRequest,
};
use crate::models::response::{
    AppResponse, CreateApiTokenResponse, CreateSessionTokenResponse, GroupApiTokenResponse,
    LoginResponse, RefreshTokenResponse, UserInfoResponse, ValidateAPITokenResponse,
    ValidateTokenResponse,
};
use crate::models::schema::{
    Api_Token, Api_TokenInsertable, App, AppInsertable, Group, GroupInsertable,
    Group_OwnersInsertable, Group_UsersInsertable, User, UserInsertable,
};
use rand::distributions::Alphanumeric;
use NotificationService::models::EmailRequest;

use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use base32::Alphabet;
use spki::EncodePublicKey;
use serde::Deserialize;
use sec1::DecodeEcPrivateKey;
use crate::models::request::DockerAccess;
use p256::pkcs8::EncodePrivateKey;

// ============================================================================
// Shared, descriptive JSON error type — mirrors the ApiError used in the
// dbschema/services router so both services return a consistent error shape:
//   { "error": true, "message": "<handler>: <what failed>" }
//
// Every handler below returns `ApiError` instead of a bare `rocket::http::
// Status` (no body) or `status::Custom<String>` (plain text, inconsistent
// shape). This also means the underlying diesel/redis/bcrypt/jwt error is
// preserved in the message and logged server-side via eprintln!, instead of
// being discarded by `.map_err(|_| Status::X)` or crashing the worker via
// `.expect()` / `.unwrap()`.
//
// If you have multiple route files, consider moving this into a shared
// `src/errors.rs` module instead of duplicating it per file.
// ============================================================================

#[derive(Serialize, JsonSchema)]
pub struct ApiError {
    pub error: bool,
    pub message: String,
    #[serde(skip)]
    #[schemars(skip)]
    pub status_code: u16,
}

impl ApiError {
    /// Build a new ApiError. `context` should be `"handler_name: what failed"`,
    /// e.g. `"login: verifying password"`.
    pub fn new(status: Status, context: &str) -> Self {
        ApiError {
            error: true,
            message: context.to_string(),
            status_code: status.code,
        }
    }

    /// Build an ApiError from a lower-level error (diesel, redis, bcrypt,
    /// jwt, serde_json, etc.), logging the raw debug output server-side and
    /// returning a descriptive (but not internals-leaking) message.
    pub fn from_err<E: std::fmt::Debug>(status: Status, context: &str, err: E) -> Self {
        eprintln!("[ERROR] {} -> {:?}", context, err);
        ApiError {
            error: true,
            message: format!("{}: {:?}", context, err),
            status_code: status.code,
        }
    }

    pub fn not_found(context: &str) -> Self {
        Self::new(Status::NotFound, context)
    }

    pub fn unauthorized(context: &str) -> Self {
        Self::new(Status::Unauthorized, context)
    }

    pub fn forbidden(context: &str) -> Self {
        Self::new(Status::Forbidden, context)
    }

    pub fn bad_request(context: &str) -> Self {
        Self::new(Status::BadRequest, context)
    }

    pub fn conflict(context: &str) -> Self {
        Self::new(Status::Conflict, context)
    }

    pub fn service_unavailable(context: &str) -> Self {
        Self::new(Status::ServiceUnavailable, context)
    }

    pub fn internal<E: std::fmt::Debug>(context: &str, err: E) -> Self {
        Self::from_err(Status::InternalServerError, context, err)
    }
}

impl<'r> Responder<'r, 'static> for ApiError {
    fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
        let status = Status::from_code(self.status_code).unwrap_or(Status::InternalServerError);
        let body = serde_json::to_string(&self)
            .unwrap_or_else(|_| "{\"error\":true,\"message\":\"Unknown error\"}".to_string());
        rocket::Response::build()
            .status(status)
            .header(ContentType::JSON)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{RefOr, Response as OpenApiResponse, Responses};
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::OpenApiError;

impl OpenApiResponderInner for ApiError {
    fn responses(gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();

        let schema = gen.json_schema::<ApiError>();
        let response = OpenApiResponse {
            description: "An error occurred".to_string(),
            content: {
                let mut content = okapi::map! {};
                content.insert(
                    "application/json".to_string(),
                    rocket_okapi::okapi::openapi3::MediaType {
                        schema: Some(schema),
                        ..Default::default()
                    },
                );
                content
            },
            ..Default::default()
        };

        for code in ["400", "401", "403", "404", "409", "500", "503"] {
            responses
                .responses
                .insert(code.to_string(), RefOr::Object(response.clone()));
        }

        Ok(responses)
    }
}

// Small helpers: get a DB / Redis connection or return a descriptive,
// consistent error instead of `.expect()`-panicking the worker thread.
fn get_conn(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    context: &str,
) -> Result<diesel::r2d2::PooledConnection<ConnectionManager<PgConnection>>, ApiError> {
    rdb.get().map_err(|e| {
        ApiError::from_err(
            Status::ServiceUnavailable,
            &format!("{}: failed to get DB connection", context),
            e,
        )
    })
}

fn get_cache_conn(
    cache: &State<Pool<RedisConnectionManager>>,
    context: &str,
) -> Result<diesel::r2d2::PooledConnection<RedisConnectionManager>, ApiError> {
    cache.get().map_err(|e| {
        ApiError::from_err(
            Status::ServiceUnavailable,
            &format!("{}: failed to get Redis connection", context),
            e,
        )
    })
}

// ── Shared structs for docker token ─────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct DockerTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    nbf: usize,
    iat: usize,
    jti: String,
    access: Vec<DockerAccess>,
}

#[openapi()]
#[post("/change-password", data = "<change_password_request>")]
pub fn change_password(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    change_password_request: Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = get_conn(rdb, "change_password")?;

    let u: User = user
        .filter(email_id.eq(&change_password_request.email))
        .first(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!(
                    "change_password: user with email '{}' not found",
                    change_password_request.email
                ),
                e,
            )
        })?;

    let hash_val = u.password_hash.as_ref().ok_or_else(|| {
        ApiError::internal(
            &format!("change_password: user '{}' has no password hash set", u.email_id),
            "password_hash column was NULL",
        )
    })?;

    let valid = verify(&change_password_request.current_password, hash_val).map_err(|e| {
        ApiError::internal(
            &format!("change_password: bcrypt verify for user '{}'", u.email_id),
            e,
        )
    })?;

    if !valid {
        return Err(ApiError::unauthorized(&format!(
            "change_password: current password incorrect for user '{}'",
            u.email_id
        )));
    }

    let new_hashed_password = hash(&change_password_request.new_password, DEFAULT_COST)
        .map_err(|e| ApiError::internal("change_password: hashing new password", e))?;

    let updated_rows = update(user.filter(email_id.eq(&change_password_request.email)))
        .set(password_hash.eq(Some(new_hashed_password)))
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("change_password: updating password for user '{}'", u.email_id),
                e,
            )
        })?;

    if updated_rows > 0 {
        Ok(Json(MessageResponse {
            message: "Password updated successfully".to_string(),
        }))
    } else {
        Err(ApiError::internal(
            &format!("change_password: update touched 0 rows for user '{}'", u.email_id),
            "expected 1 row to be updated",
        ))
    }
}

#[openapi()]
#[post("/register", data = "<register_request>")]
pub async fn register(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    register_request: Json<RegisterRequest>,
) -> Result<Json<String>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = get_conn(rdb, "register")?;
    let mut cache_connection = get_cache_conn(cache, "register")?;

    let existing_user = user
        .filter(email_id.eq(&register_request.email))
        .first::<User>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "register: checking for existing user with email '{}'",
                    register_request.email
                ),
                e,
            )
        })?;

    if existing_user.is_some() {
        return Err(ApiError::conflict(&format!(
            "register: a user with email '{}' already exists",
            register_request.email
        )));
    }

    let hashed_password = hash(&register_request.password, DEFAULT_COST)
        .map_err(|e| ApiError::internal("register: hashing password", e))?;

    let registration_token_value: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let registration_cache_value = RegisterRequestValue {
        email: register_request.email.clone(),
        hashed_password,
    };

    let serialized = serde_json::to_string(&registration_cache_value).map_err(|e| {
        ApiError::internal("register: serializing pending registration payload", e)
    })?;

    let _: () = cache_connection
        .set_ex(&registration_token_value, serialized, 300) // Token expires in 5 minutes
        .map_err(|e| {
            ApiError::internal(
                "register: caching pending registration token",
                e,
            )
        })?;

    let mut configuration = get_notification_service_configuration();

    let token_str = env::var("ISC_SECRET").map_err(|e| {
        ApiError::internal("register: reading ISC_SECRET env var", e)
    })?;

    configuration.api_key = Some(NotificationApiKey {
        key: token_str,
        prefix: None,
    });

    match send_email(
            &configuration,
            SendEmailParams {
                email_request: EmailRequest {
                    to: register_request.email.clone(),
                    subject: "Confirm Registration".to_string(),
                    message: format!("Use this link (expires within 5 minutes) to confirm your registration: https://iam-staging.gingersociety.org/#/{}/registration-confirmation/{}", register_request.app_id, registration_token_value),
                    reply_to: None,
                },
            },
        ).await {
            Ok(_) => Ok(Json(
                "User registration request generated successfully".to_string(),
            )),
            Err(e) => Err(ApiError::from_err(
                Status::ServiceUnavailable,
                &format!("register: sending confirmation email to '{}'", register_request.email),
                e,
            )),
        }
}

#[openapi()]
#[get("/confirm-register/<registration_token>")]
pub fn registeration_confirmation(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    registration_token: String,
) -> Result<Json<String>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = get_conn(rdb, "registeration_confirmation")?;
    let mut cache_connection = get_cache_conn(cache, "registeration_confirmation")?;

    let user_data: String = cache_connection.get(&registration_token).map_err(|e| {
        ApiError::from_err(
            Status::NotFound,
            &format!(
                "registeration_confirmation: registration token '{}' not found or expired",
                registration_token
            ),
            e,
        )
    })?;

    // Remove the token from cache after reading (best-effort; log but don't
    // fail the confirmation if cleanup fails).
    if let Err(e) = cache_connection.del::<_, ()>(&registration_token) {
        eprintln!(
            "[WARN] registeration_confirmation: failed to delete used token '{}' -> {:?}",
            registration_token, e
        );
    }

    let register_request: RegisterRequestValue = serde_json::from_str(&user_data).map_err(|e| {
        ApiError::internal(
            "registeration_confirmation: deserializing cached registration payload",
            e,
        )
    })?;

    let new_user = UserInsertable {
        first_name: None,
        last_name: None,
        middle_name: None,
        email_id: register_request.email.clone(),
        mobile_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        password_hash: Some(register_request.hashed_password),
        is_root: false,
        is_active: true,
    };

    insert_into(user)
        .values(&new_user)
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "registeration_confirmation: inserting new user '{}'",
                    register_request.email
                ),
                e,
            )
        })?;

    Ok(Json("User registered successfully".to_string()))
}

fn user_has_access_to_app(
    conn: &mut PgConnection,
    app_id: &String,
    user_groups: &[String],
) -> Result<bool, diesel::result::Error> {
    use crate::models::schema::schema::app::dsl as app_dsl;
    use crate::models::schema::schema::group::dsl as group_dsl;

    // Check if the app exists and is not disabled
    let app = match app_dsl::app
        .filter(app_dsl::client_id.eq(app_id))
        .filter(app_dsl::disabled.eq(false))
        .first::<App>(conn)
    {
        Ok(app) => app,
        Err(_) => {
            eprintln!("[user_has_access_to_app] app does not exist or is disabled: {}", app_id);
            return Ok(false);
        }
    };

    let group_ids: Vec<i64> = user_groups
        .iter()
        .filter_map(|group| group.parse::<i64>().ok())
        .collect();

    // Step 1: Check if app.group_id is NULL (public app)
    if app.group_id.is_none() {
        return Ok(true);
    }

    // Step 2: Check if app.group_id matches user groups
    let accessible_app_exists = app_dsl::app
        .left_join(group_dsl::group.on(group_dsl::id.nullable().eq(app_dsl::group_id)))
        .filter(app_dsl::client_id.eq(app_id))
        .filter(
            group_dsl::identifier
                .eq_any(user_groups)
                .or(group_dsl::id.eq_any(&group_ids)),
        )
        .select(app_dsl::id)
        .first::<i64>(conn)
        .optional()?;

    Ok(accessible_app_exists.is_some())
}

#[openapi()]
#[post("/login", data = "<login_request>")]
pub fn login(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    login_request: Json<LoginRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<IAMLoginResponse>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;
    use bcrypt::verify;

    let mut conn = get_conn(rdb, "login")?;
    let mut cache_connection = get_cache_conn(cache_pool, "login")?;

    // Fetch the user by email
    let u: User = user
        .filter(email_id.eq(&login_request.email))
        .first(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::Unauthorized,
                &format!("login: user not found for email '{}'", login_request.email),
                e,
            )
        })?;

    // Check password hash is present
    let hash_val = u.password_hash.as_ref().ok_or_else(|| {
        ApiError::unauthorized(&format!(
            "login: user '{}' has no password hash set",
            u.email_id
        ))
    })?;

    // Verify the password
    let valid = verify(&login_request.password, hash_val).map_err(|e| {
        ApiError::from_err(
            Status::Unauthorized,
            &format!("login: bcrypt verify error for user '{}'", u.email_id),
            e,
        )
    })?;

    if !valid {
        return Err(ApiError::unauthorized(&format!(
            "login: invalid password for user '{}'",
            u.email_id
        )));
    }

    // Fetch user_groups from cache or database
    let cache_key = format!("user_groups:{}", u.id);
    let user_groups: Vec<String> = match cache_connection.get::<_, Option<String>>(&cache_key) {
        Ok(Some(cached_groups)) => serde_json::from_str(&cached_groups).unwrap_or_else(|e| {
            eprintln!(
                "[WARN] login: failed to deserialize cached groups for user {} -> {:?}",
                u.id, e
            );
            vec![]
        }),
        Ok(None) => {
            use crate::models::schema::schema::group::dsl as group_dsl;
            use crate::models::schema::schema::group_users::dsl as gu_dsl;

            let groups_from_db: Vec<String> = gu_dsl::group_users
                .inner_join(group_dsl::group.on(group_dsl::id.eq(gu_dsl::group_id)))
                .filter(gu_dsl::user_id.eq(u.id))
                .select(group_dsl::identifier)
                .load(&mut conn)
                .map_err(|e| {
                    ApiError::internal(
                        &format!("login: loading groups from DB for user {}", u.id),
                        e,
                    )
                })?;

            let groups_json = serde_json::to_string(&groups_from_db).unwrap_or_default();
            if let Err(e) = cache_connection.set_ex::<_, _, ()>(&cache_key, groups_json, 3600) {
                eprintln!(
                    "[WARN] login: failed to cache user_groups for user {} -> {:?}",
                    u.id, e
                );
            }

            groups_from_db
        }
        Err(e) => {
            eprintln!(
                "[WARN] login: Redis error fetching user_groups for user {} -> {:?}",
                u.id, e
            );
            vec![]
        }
    };

    // Determine app_id for Redis cache
    let app_id = login_request.client_id.clone();

    let app_tokens = if let Some(app_id) = &app_id {
        match user_has_access_to_app(&mut conn, app_id, &user_groups) {
            Ok(true) => {
                let access_token = create_jwt(
                    &u.email_id,
                    &u.id.to_string(),
                    "access",
                    &u.first_name,
                    &u.last_name,
                    &u.middle_name,
                    &Some(app_id.clone()),
                )?;
                let refresh_token = create_jwt(
                    &u.email_id,
                    &u.id.to_string(),
                    "refresh",
                    &u.first_name,
                    &u.last_name,
                    &u.middle_name,
                    &Some(app_id.clone()),
                )?;

                let session_data_with_app = json!({
                    "user_id": u.id,
                    "app_id": app_id,
                });
                let _: () = cache_connection
                    .set_ex(
                        refresh_token.clone(),
                        session_data_with_app.to_string(),
                        3600,
                    )
                    .map_err(|e| {
                        ApiError::internal(
                            &format!("login: caching app session for app '{}'", app_id),
                            e,
                        )
                    })?;

                Some(LoginResponse {
                    access_token,
                    refresh_token,
                })
            }
            Ok(false) => {
                return Err(ApiError::forbidden(&format!(
                    "login: user '{}' does not have access to app '{}' (groups: {:?})",
                    u.email_id, app_id, user_groups
                )));
            }
            Err(e) => {
                return Err(ApiError::internal(
                    &format!(
                        "login: checking app access for user '{}' / app '{}'",
                        u.email_id, app_id
                    ),
                    e,
                ));
            }
        }
    } else {
        None
    };

    // Create tokens without app_id
    let access_token_without_app = create_jwt(
        &u.email_id,
        &u.id.to_string(),
        "access",
        &u.first_name,
        &u.last_name,
        &u.middle_name,
        &None,
    )?;
    let refresh_token_without_app = create_jwt(
        &u.email_id,
        &u.id.to_string(),
        "refresh",
        &u.first_name,
        &u.last_name,
        &u.middle_name,
        &None,
    )?;

    let session_data_without_app = json!({ "user_id": u.id });
    let _: () = cache_connection
        .set_ex(
            refresh_token_without_app.clone(),
            session_data_without_app.to_string(),
            3600,
        )
        .map_err(|e| {
            ApiError::internal(
                &format!("login: caching base IAM session for user '{}'", u.email_id),
                e,
            )
        })?;

    Ok(Json(IAMLoginResponse {
        app_tokens,
        iam_tokens: LoginResponse {
            access_token: access_token_without_app,
            refresh_token: refresh_token_without_app,
        },
    }))
}

#[openapi()]
#[post("/refresh-token", data = "<refresh_request>")]
pub fn refresh_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    refresh_request: Json<RefreshTokenRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<RefreshTokenResponse>, ApiError> {
    let mut cache_connection = get_cache_conn(cache_pool, "refresh_token")?;

    let secret = env::var("JWT_SECRET")
        .map_err(|e| ApiError::internal("refresh_token: reading JWT_SECRET env var", e))?;
    let decoding_key = DecodingKey::from_secret(secret.as_ref());

    let token_data = decode::<Claims>(
        &refresh_request.refresh_token,
        &decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| {
        ApiError::from_err(Status::Unauthorized, "refresh_token: decoding refresh token", e)
    })?;

    if token_data.claims.token_type != "refresh" {
        return Err(ApiError::unauthorized(&format!(
            "refresh_token: expected token_type 'refresh', got '{}'",
            token_data.claims.token_type
        )));
    }

    let refresh_token_exists: bool = cache_connection
        .exists(&refresh_request.refresh_token)
        .map_err(|e| {
            ApiError::internal("refresh_token: checking refresh token existence in Redis", e)
        })?;

    if !refresh_token_exists {
        return Err(ApiError::unauthorized(
            "refresh_token: refresh token not found in Redis (expired or revoked)",
        ));
    }

    let access_token = create_jwt(
        &token_data.claims.sub,
        &token_data.claims.user_id,
        "access",
        &token_data.claims.first_name,
        &token_data.claims.last_name,
        &token_data.claims.middle_name,
        &token_data.claims.client_id,
    )?;

    Ok(Json(RefreshTokenResponse { access_token }))
}

#[openapi()]
#[get("/validate")]
pub fn validate_token(claims: Claims) -> Json<ValidateTokenResponse> {
    Json(ValidateTokenResponse {
        sub: claims.sub,
        exp: claims.exp,
        user_id: claims.user_id,
        first_name: claims.first_name,
        last_name: claims.last_name,
        middle_name: claims.middle_name,
        client_id: claims.client_id,
    })
}

#[openapi()]
#[get("/validate-api-token")]
pub fn validate_api_token(claims: APIClaims) -> Json<ValidateAPITokenResponse> {
    Json(ValidateAPITokenResponse {
        sub: claims.sub,
        exp: claims.exp,
        group_id: claims.group_id,
        scopes: claims.scopes,
    })
}

/// Builds a signed JWT. Returns `ApiError` instead of panicking so a bad
/// JWT_SECRET or an unexpected token_type surfaces as a normal 500 response
/// rather than taking down the worker thread.
fn create_jwt(
    email: &str,
    uid: &str,
    token_type: &str,
    f_name: &Option<String>,
    l_name: &Option<String>,
    m_name: &Option<String>,
    c_id: &Option<String>,
) -> Result<String, ApiError> {
    let expiration = match token_type {
        "access" => Utc::now() + Duration::minutes(15), // Short-lived access token
        "refresh" => Utc::now() + Duration::hours(10),  // Longer-lived refresh token
        other => {
            return Err(ApiError::internal(
                "create_jwt: invalid token_type requested",
                format!("expected 'access' or 'refresh', got '{}'", other),
            ))
        }
    };
    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration.timestamp() as usize,
        user_id: uid.to_owned(),
        token_type: token_type.to_owned(),
        first_name: f_name.clone(),
        last_name: l_name.clone(),
        middle_name: m_name.clone(),
        client_id: c_id.clone(),
    };
    let secret =
        env::var("JWT_SECRET").map_err(|e| ApiError::internal("create_jwt: reading JWT_SECRET env var", e))?;
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| ApiError::internal(&format!("create_jwt: encoding '{}' token", token_type), e))
}

#[openapi()]
#[put("/update-profile", data = "<update_request>")]
pub fn update_profile(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    update_request: Json<UpdateProfileRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let mut conn = get_conn(rdb, "update_profile")?;

    use crate::models::schema::schema::user::dsl::*;

    let user_id_val = claims.user_id.parse::<i64>().map_err(|e| {
        ApiError::internal(
            &format!("update_profile: parsing claims.user_id '{}' as i64", claims.user_id),
            e,
        )
    })?;

    let updated_rows = diesel::update(user.filter(id.eq(user_id_val)))
        .set((
            first_name.eq(&update_request.first_name),
            middle_name.eq(&update_request.middle_name),
            last_name.eq(&update_request.last_name),
            mobile_number.eq(&update_request.mobile_number),
        ))
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("update_profile: updating profile for user id={}", user_id_val),
                e,
            )
        })?;

    if updated_rows > 0 {
        Ok(Json(MessageResponse {
            message: "Profile updated successfully".to_string(),
        }))
    } else {
        Err(ApiError::not_found(&format!(
            "update_profile: no user found with id={}",
            user_id_val
        )))
    }
}

#[openapi]
#[get("/app-details/<client_id_>")]
pub fn get_app_by_client_id(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    client_id_: String,
) -> Result<Json<AppResponse>, ApiError> {
    use crate::models::schema::schema::app::dsl::*;

    let mut conn = get_conn(rdb, "get_app_by_client_id")?;

    let a = app
        .filter(client_id.eq(&client_id_))
        .filter(disabled.eq(false))
        .first::<App>(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!(
                    "get_app_by_client_id: app with client_id '{}' not found or disabled",
                    client_id_
                ),
                e,
            )
        })?;

    Ok(Json(AppResponse {
        name: a.name,
        logo_url: a.logo_url,
        app_url_dev: a.app_url_dev,
        app_url_stage: a.app_url_stage,
        app_url_prod: a.app_url_prod,
        tnc_link: a.tnc_link,
        allow_registration: a.allow_registration,
        redirection_path: a.auth_redirection_path,
    }))
}

#[openapi]
#[get("/group-memberships")]
pub fn get_group_memberships(claims: Claims, groups: GroupMemberships) -> Json<Vec<String>> {
    Json(groups.0)
}

#[openapi]
#[get("/group-ownerships")]
pub fn get_group_ownserships(claims: Claims, groups_owned: GroupOwnerships) -> Json<Vec<String>> {
    Json(groups_owned.0)
}

#[openapi]
#[get("/clear-redis")]
pub fn clear_redis(
    claims: Claims,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<String>, ApiError> {
    let mut cache_connection = get_cache_conn(cache_pool, "clear_redis")?;

    let cache_key = format!("user_groups:{}", claims.user_id);
    let cache_key_2 = format!("groups_owned:{}", claims.user_id);

    cache_connection.del::<_, i32>(&cache_key).map_err(|e| {
        ApiError::internal(
            &format!("clear_redis: deleting key '{}'", cache_key),
            e,
        )
    })?;

    cache_connection.del::<_, i32>(&cache_key_2).map_err(|e| {
        ApiError::internal(
            &format!("clear_redis: deleting key '{}'", cache_key_2),
            e,
        )
    })?;

    Ok(Json("Successfully cleared Redis cache.".to_string()))
}

#[openapi()]
#[post("/create-group", data = "<create_request>")]
pub fn create_group(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    create_request: Json<CreateGroupRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<Group>, ApiError> {
    use crate::models::schema::schema::group::dsl::*;
    use crate::models::schema::schema::group_owners::dsl::*;
    use crate::models::schema::schema::group_users::dsl::*;

    let mut conn = get_conn(rdb, "create_group")?;
    let mut cache_connection = get_cache_conn(cache_pool, "create_group")?;

    let group_exists = group
        .filter(identifier.eq(&create_request.id))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!("create_group: checking if group '{}' already exists", create_request.id),
                e,
            )
        })?;

    if group_exists.is_some() {
        return Err(ApiError::conflict(&format!(
            "create_group: a group with identifier '{}' already exists",
            create_request.id
        )));
    }

    let new_group = GroupInsertable {
        identifier: create_request.id.clone(),
        disabled: false,
        short_text: create_request.description.clone(),
    };

    let created_group = diesel::insert_into(group)
        .values(&new_group)
        .get_result::<Group>(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("create_group: inserting new group '{}'", create_request.id),
                e,
            )
        })?;

    let user_id_val = claims.user_id.parse::<i64>().map_err(|e| {
        ApiError::internal(
            &format!("create_group: parsing claims.user_id '{}' as i64", claims.user_id),
            e,
        )
    })?;

    let new_group_user = Group_UsersInsertable {
        user_id: user_id_val,
        group_id: created_group.id,
    };

    diesel::insert_into(group_users)
        .values(&new_group_user)
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "create_group: adding user {} to group id={}",
                    user_id_val, created_group.id
                ),
                e,
            )
        })?;

    let new_group_owner = Group_OwnersInsertable {
        user_id: user_id_val,
        group_id: created_group.id,
    };

    diesel::insert_into(group_owners)
        .values(&new_group_owner)
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "create_group: adding user {} as owner of group id={}",
                    user_id_val, created_group.id
                ),
                e,
            )
        })?;

    let cache_key = format!("user_groups:{}", claims.user_id);
    cache_connection.del::<_, i32>(&cache_key).map_err(|e| {
        ApiError::internal(
            &format!("create_group: clearing cached group list for user {}", claims.user_id),
            e,
        )
    })?;

    Ok(Json(created_group))
}

#[openapi()]
#[post("/request-password", data = "<request>")]
pub async fn request_password_reset(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    request: Json<RequestPasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut cache_connection = get_cache_conn(cache, "request_password_reset")?;
    let mut conn = get_conn(rdb, "request_password_reset")?;

    let u = user
        .filter(email_id.eq(&request.email_id))
        .first::<User>(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!(
                    "request_password_reset: user with email '{}' not found",
                    request.email_id
                ),
                e,
            )
        })?;

    let token_value: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let _: () = cache_connection
        .set_ex(&token_value, u.id, 300) // Token expires in 5 minutes
        .map_err(|e| {
            ApiError::internal(
                &format!("request_password_reset: caching reset token for user {}", u.id),
                e,
            )
        })?;

    let mut configuration = get_notification_service_configuration();

    let token_str = env::var("ISC_SECRET")
        .map_err(|e| ApiError::internal("request_password_reset: reading ISC_SECRET env var", e))?;

    configuration.api_key = Some(NotificationApiKey {
        key: token_str,
        prefix: None,
    });

    match send_email(
        &configuration,
        SendEmailParams {
            email_request: EmailRequest {
                to: request.email_id.clone(),
                subject: "Password Reset".to_string(),
                message: format!("Use this link(expires within 5 minutes) to reset your password: https://iam.gingersociety.org/#/public/{}/reset-password/{}", request.app_id, token_value),
                reply_to: None,
            },
        },
    )
    .await
    {
        Ok(_) => Ok(Json(MessageResponse {
            message: "Password reset token created successfully".to_string(),
        })),
        Err(e) => Err(ApiError::from_err(
            Status::ServiceUnavailable,
            &format!("request_password_reset: sending reset email to '{}'", request.email_id),
            e,
        )),
    }
}

#[openapi()]
#[post("/reset-password", data = "<request>")]
pub fn reset_password(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    request: Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut cache_connection = get_cache_conn(cache, "reset_password")?;
    let mut conn = get_conn(rdb, "reset_password")?;

    let user_id: i64 = cache_connection.get(&request.token).map_err(|e| {
        ApiError::from_err(
            Status::NotFound,
            "reset_password: reset token not found or expired",
            e,
        )
    })?;

    let new_hashed_password = hash(&request.new_password, DEFAULT_COST)
        .map_err(|e| ApiError::internal("reset_password: hashing new password", e))?;

    let updated_rows = update(user.filter(id.eq(user_id)))
        .set(password_hash.eq(Some(new_hashed_password)))
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("reset_password: updating password for user id={}", user_id),
                e,
            )
        })?;

    if updated_rows > 0 {
        if let Err(e) = cache_connection.del::<_, ()>(&request.token) {
            eprintln!(
                "[WARN] reset_password: failed to delete used reset token -> {:?}",
                e
            );
        }

        Ok(Json(MessageResponse {
            message: "Password updated successfully".to_string(),
        }))
    } else {
        Err(ApiError::internal(
            &format!("reset_password: update touched 0 rows for user id={}", user_id),
            "expected 1 row to be updated",
        ))
    }
}

#[openapi]
#[post("/create-api-token", data = "<create_request>")]
pub fn create_api_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    create_request: Json<CreateApiTokenRequest>,
    claims: Claims,
) -> Result<Json<CreateApiTokenResponse>, ApiError> {
    use crate::models::schema::schema::api_token::dsl::*;
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = get_conn(rdb, "create_api_token")?;

    let user_id = claims.user_id;
    let first_name = claims.first_name;
    let last_name = claims.last_name;
    let middle_name = claims.middle_name;
    let client_id = claims.client_id;
    let email = claims.sub;

    let expiration = Utc::now() + Duration::days(create_request.days_to_expire);
    let new_claims = Claims {
        sub: email,
        exp: expiration.timestamp() as usize,
        user_id,
        token_type: "api".to_string(),
        first_name,
        last_name,
        middle_name,
        client_id,
    };

    let secret = env::var("JWT_SECRET")
        .map_err(|e| ApiError::internal("create_api_token: reading JWT_SECRET env var", e))?;
    let token = encode(
        &Header::default(),
        &new_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| ApiError::internal("create_api_token: encoding token", e))?;

    let group: Group = group_dsl::group
        .filter(group_dsl::identifier.eq(&create_request.group_identifier))
        .first::<Group>(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!(
                    "create_api_token: group '{}' not found",
                    create_request.group_identifier
                ),
                e,
            )
        })?;

    let new_token = Api_TokenInsertable {
        parent_id: group.id,
        expiry_date: expiration.naive_utc().date(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        is_active: true,
        name: create_request.name.clone(),
        token_str: Some(token.clone()),
    };

    diesel::insert_into(api_token)
        .values(&new_token)
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("create_api_token: inserting token for group id={}", group.id),
                e,
            )
        })?;

    Ok(Json(CreateApiTokenResponse { api_token: token }))
}

#[openapi()]
#[post("/logout", data = "<logout_request>")]
pub fn logout(
    cache: &State<Pool<RedisConnectionManager>>,
    logout_request: Json<LogoutRequest>,
    claims: Claims,
) -> Result<Json<MessageResponse>, ApiError> {
    let mut cache_connection = get_cache_conn(cache, "logout")?;

    let refresh_token_key = logout_request.refresh_token.clone();
    let refresh_token_exists: bool = cache_connection.exists(&refresh_token_key).map_err(|e| {
        ApiError::internal("logout: checking refresh token existence in Redis", e)
    })?;

    if !refresh_token_exists {
        return Ok(Json(MessageResponse {
            message: "Logged out successfully".to_string(),
        }));
    }

    let _: () = cache_connection.del(&refresh_token_key).map_err(|e| {
        ApiError::internal("logout: deleting refresh token from Redis", e)
    })?;

    Ok(Json(MessageResponse {
        message: "Logged out successfully".to_string(),
    }))
}

#[openapi()]
#[get("/get_members/<group_param>")]
pub fn get_members(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_param: String,
) -> Result<Json<Vec<UserInfoResponse>>, ApiError> {
    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_owners::dsl as group_owners_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    use crate::models::schema::schema::user::dsl as users_dsl;

    let mut conn = get_conn(rdb, "get_members")?;

    let group_query: Box<dyn BoxableExpression<group_dsl::group, Pg, SqlType = Bool>> =
        if let Ok(group_id) = group_param.parse::<i64>() {
            Box::new(group_dsl::id.eq(group_id))
        } else {
            Box::new(group_dsl::identifier.eq(group_param.clone()))
        };

    let group_id = group_dsl::group
        .filter(group_query)
        .select(group_dsl::id)
        .first::<i64>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!("get_members: looking up group '{}'", group_param),
                e,
            )
        })?
        .ok_or_else(|| {
            ApiError::not_found(&format!("get_members: group '{}' not found", group_param))
        })?;

    let users = group_users_dsl::group_users
        .inner_join(users_dsl::user.on(users_dsl::id.eq(group_users_dsl::user_id)))
        .filter(group_users_dsl::group_id.eq(group_id))
        .select((
            users_dsl::first_name.nullable(),
            users_dsl::last_name.nullable(),
            users_dsl::middle_name.nullable(),
            users_dsl::email_id,
            users_dsl::id,
        ))
        .load::<(Option<String>, Option<String>, Option<String>, String, i64)>(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("get_members: loading users for group id={}", group_id),
                e,
            )
        })?;

    let group_owners: Vec<i64> = group_owners_dsl::group_owners
        .filter(group_owners_dsl::group_id.eq(group_id))
        .select(group_owners_dsl::user_id)
        .load(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("get_members: loading owners for group id={}", group_id),
                e,
            )
        })?;

    let user_info: Vec<UserInfoResponse> = users
        .into_iter()
        .map(
            |(first_name, last_name, middle_name, email_id, pk)| UserInfoResponse {
                first_name: first_name.unwrap_or_default(),
                last_name: last_name.unwrap_or_default(),
                middle_name,
                pk,
                is_admin: group_owners.contains(&pk),
                email_id,
            },
        )
        .collect();

    Ok(Json(user_info))
}

fn fetch_group_members_ids(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: &str,
) -> Result<Vec<i64>, ApiError> {
    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    let mut conn = get_conn(rdb, "fetch_group_members_ids")?;

    let group_id = group_dsl::group
        .filter(group_dsl::identifier.eq(group_identifier))
        .select(group_dsl::id)
        .first::<i64>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!("fetch_group_members_ids: looking up group '{}'", group_identifier),
                e,
            )
        })?
        .ok_or_else(|| {
            ApiError::not_found(&format!(
                "fetch_group_members_ids: group '{}' not found",
                group_identifier
            ))
        })?;

    let user_ids = group_users_dsl::group_users
        .filter(group_users_dsl::group_id.eq(group_id))
        .select(group_users_dsl::user_id)
        .load::<i64>(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("fetch_group_members_ids: loading user ids for group id={}", group_id),
                e,
            )
        })?;

    Ok(user_ids)
}

#[openapi()]
#[get("/api-land/get_group_members_ids/<group_identifier>")]
pub fn get_group_members_ids_api_land(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
    _claims: APIClaims,
) -> Result<Json<Vec<i64>>, ApiError> {
    Ok(Json(fetch_group_members_ids(rdb, &group_identifier)?))
}

#[openapi()]
#[get("/user-land/get_group_members_ids/<group_identifier>")]
pub fn get_group_members_ids_user_land(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
    _claims: Claims,
) -> Result<Json<Vec<i64>>, ApiError> {
    Ok(Json(fetch_group_members_ids(rdb, &group_identifier)?))
}

#[openapi()]
#[get("/get_group_members_ids/<group_identifier>")]
pub fn get_group_members_ids(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
    _claims: ISCClaims,
) -> Result<Json<Vec<i64>>, ApiError> {
    Ok(Json(fetch_group_members_ids(rdb, &group_identifier)?))
}

#[openapi()]
#[put("/manage-membership/<group_param>/<user_id>/<action>")]
pub fn manage_membership(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_param: String,
    user_id: String,
    action: String,
) -> Result<Json<Value>, ApiError> {
    let mut conn = get_conn(rdb, "manage_membership")?;

    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_owners::dsl as group_owners_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    use crate::models::schema::schema::user::dsl as user_dsl;

    let group_query: Box<dyn BoxableExpression<group_dsl::group, Pg, SqlType = Bool>> =
        if let Ok(group_id) = group_param.parse::<i64>() {
            Box::new(group_dsl::id.eq(group_id))
        } else {
            Box::new(group_dsl::identifier.eq(group_param.clone()))
        };

    let group: Group = group_dsl::group
        .filter(group_query)
        .first::<Group>(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!("manage_membership: group '{}' not found", group_param),
                e,
            )
        })?;

    let user: User = user_dsl::user
        .filter(user_dsl::email_id.eq(&user_id))
        .first::<User>(&mut conn)
        .map_err(|e| {
            ApiError::from_err(
                Status::NotFound,
                &format!("manage_membership: user '{}' not found", user_id),
                e,
            )
        })?;

    match action.as_str() {
        "add-member" => {
            diesel::delete(
                group_owners_dsl::group_owners
                    .filter(group_owners_dsl::user_id.eq(user.id))
                    .filter(group_owners_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|e| {
                ApiError::internal(
                    &format!(
                        "manage_membership: removing user {} from owners of group {}",
                        user.id, group.id
                    ),
                    e,
                )
            })?;

            diesel::insert_into(group_users_dsl::group_users)
                .values((
                    group_users_dsl::user_id.eq(user.id),
                    group_users_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|e| {
                    ApiError::internal(
                        &format!(
                            "manage_membership: adding user {} as member of group {}",
                            user.id, group.id
                        ),
                        e,
                    )
                })?;
        }
        "add-admin" => {
            diesel::insert_into(group_users_dsl::group_users)
                .values((
                    group_users_dsl::user_id.eq(user.id),
                    group_users_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|e| {
                    ApiError::internal(
                        &format!(
                            "manage_membership: adding user {} as member of group {}",
                            user.id, group.id
                        ),
                        e,
                    )
                })?;

            diesel::insert_into(group_owners_dsl::group_owners)
                .values((
                    group_owners_dsl::user_id.eq(user.id),
                    group_owners_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|e| {
                    ApiError::internal(
                        &format!(
                            "manage_membership: adding user {} as owner of group {}",
                            user.id, group.id
                        ),
                        e,
                    )
                })?;
        }
        "remove" => {
            diesel::delete(
                group_users_dsl::group_users
                    .filter(group_users_dsl::user_id.eq(user.id))
                    .filter(group_users_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|e| {
                ApiError::internal(
                    &format!(
                        "manage_membership: removing user {} from members of group {}",
                        user.id, group.id
                    ),
                    e,
                )
            })?;

            diesel::delete(
                group_owners_dsl::group_owners
                    .filter(group_owners_dsl::user_id.eq(user.id))
                    .filter(group_owners_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|e| {
                ApiError::internal(
                    &format!(
                        "manage_membership: removing user {} from owners of group {}",
                        user.id, group.id
                    ),
                    e,
                )
            })?;
        }
        other => {
            return Err(ApiError::bad_request(&format!(
                "manage_membership: unknown action '{}' (expected add-member, add-admin, or remove)",
                other
            )))
        }
    }

    Ok(Json(json!({ "status": "success" })))
}

#[openapi()]
#[post("/create-api-session-token", data = "<request>")]
pub fn create_api_session_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    request: Json<CreateSessionTokenRequest>,
) -> Result<Json<CreateSessionTokenResponse>, ApiError> {
    use crate::models::schema::schema::api_token::dsl as api_token_dsl;
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = get_conn(rdb, "create_api_session_token")?;

    let result: Option<(Api_Token, Group)> = api_token_dsl::api_token
        .inner_join(group_dsl::group.on(group_dsl::id.eq(api_token_dsl::parent_id)))
        .filter(api_token_dsl::token_str.eq(&request.api_token))
        .filter(api_token_dsl::is_active.eq(true))
        .select((Api_Token::as_select(), Group::as_select()))
        .first::<(Api_Token, Group)>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                "create_api_session_token: looking up API token",
                e,
            )
        })?;

    let (api_token, group) = result.ok_or_else(|| {
        ApiError::unauthorized("create_api_session_token: API token not found or inactive")
    })?;

    let expiration = match request.days_to_expire {
        Some(days) => Utc::now() + Duration::days(days as i64),
        None => Utc::now() + Duration::minutes(20),
    };
    let claims = APIClaims {
        sub: group.identifier.clone(), // this is the group uuid
        exp: expiration.timestamp() as usize,
        group_id: api_token.parent_id,
        scopes: vec!["read".to_string(), "write".to_string()],
    };

    let secret = env::var("JWT_SECRET").map_err(|e| {
        ApiError::internal("create_api_session_token: reading JWT_SECRET env var", e)
    })?;
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| ApiError::internal("create_api_session_token: encoding session token", e))?;

    Ok(Json(CreateSessionTokenResponse {
        session_token: token,
        group_identifier: group.identifier,
    }))
}

/// this is used by the developers on their machine for creating a session. This assumes that there is an active session on the machine
#[openapi()]
#[post("/create-api-session-token-interactive/<group_identifier>")]
pub fn create_api_session_token_interactive(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    group_identifier: String,
    groups_ownerships: GroupOwnerships,
) -> Result<Json<CreateSessionTokenResponse>, ApiError> {
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = get_conn(rdb, "create_api_session_token_interactive")?;

    let group = group_dsl::group
        .filter(group_dsl::identifier.eq(group_identifier.clone()))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "create_api_session_token_interactive: looking up group '{}'",
                    group_identifier
                ),
                e,
            )
        })?
        .ok_or_else(|| {
            ApiError::not_found(&format!(
                "create_api_session_token_interactive: group '{}' not found",
                group_identifier
            ))
        })?;

    // Determine the scope based on ownership
    let scopes = if groups_ownerships.0.contains(&group_identifier) {
        vec!["read".to_string(), "write".to_string()]
    } else {
        vec!["read".to_string()]
    };

    let expiration = Utc::now() + Duration::hours(10);
    let claims = APIClaims {
        sub: group.identifier.clone(),
        exp: expiration.timestamp() as usize,
        group_id: group.id,
        scopes,
    };

    let secret = env::var("JWT_SECRET").map_err(|e| {
        ApiError::internal(
            "create_api_session_token_interactive: reading JWT_SECRET env var",
            e,
        )
    })?;
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| {
        ApiError::internal(
            "create_api_session_token_interactive: encoding session token",
            e,
        )
    })?;

    Ok(Json(CreateSessionTokenResponse {
        session_token: token,
        group_identifier: group.identifier,
    }))
}

#[openapi()]
#[get("/api-tokens/<group_identifier>")]
pub fn get_api_tokens_by_group(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
) -> Result<Json<Vec<GroupApiTokenResponse>>, ApiError> {
    use crate::models::schema::schema::api_token::dsl as api_token_dsl;
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = get_conn(rdb, "get_api_tokens_by_group")?;

    let group = group_dsl::group
        .filter(group_dsl::identifier.eq(&group_identifier))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!("get_api_tokens_by_group: looking up group '{}'", group_identifier),
                e,
            )
        })?
        .ok_or_else(|| {
            ApiError::not_found(&format!(
                "get_api_tokens_by_group: group '{}' not found",
                group_identifier
            ))
        })?;

    let tokens = api_token_dsl::api_token
        .filter(api_token_dsl::parent_id.eq(group.id))
        .load::<Api_Token>(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("get_api_tokens_by_group: loading tokens for group id={}", group.id),
                e,
            )
        })?;

    let response: Vec<GroupApiTokenResponse> = tokens
        .into_iter()
        .map(|t| GroupApiTokenResponse {
            expiry_date: t.expiry_date,
            created_at: t.created_at,
            is_active: t.is_active,
            name: t.name,
            pk: t.id,
        })
        .collect();

    Ok(Json(response))
}

#[openapi()]
#[put("/api-tokens/<token_id>/deactivate")]
pub fn deactivate_api_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    token_id: i64,
) -> Result<Json<MessageResponse>, ApiError> {
    use crate::models::schema::schema::api_token::dsl::*;

    let mut conn = get_conn(rdb, "deactivate_api_token")?;

    let token = api_token
        .find(token_id)
        .first::<Api_Token>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!("deactivate_api_token: looking up token id={}", token_id),
                e,
            )
        })?;

    if token.is_none() {
        return Err(ApiError::not_found(&format!(
            "deactivate_api_token: token id={} not found",
            token_id
        )));
    }

    diesel::update(api_token.filter(id.eq(token_id)))
        .set(is_active.eq(false))
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("deactivate_api_token: deactivating token id={}", token_id),
                e,
            )
        })?;

    Ok(Json(MessageResponse {
        message: format!("API token with id '{}' has been deactivated", token_id),
    }))
}

#[openapi()]
#[post("/accept-invite/<invitation_token>", data = "<accept_request>")]
pub fn accept_invite(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    invitation_token: String,
    accept_request: Json<AcceptInviteRequest>,
) -> Result<Json<String>, ApiError> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = get_conn(rdb, "accept_invite")?;
    let mut cache_connection = get_cache_conn(cache, "accept_invite")?;

    let invite_data: String = cache_connection.get(&invitation_token).map_err(|e| {
        ApiError::from_err(
            Status::NotFound,
            "accept_invite: invitation token not found or expired",
            e,
        )
    })?;

    if let Err(e) = cache_connection.del::<_, ()>(&invitation_token) {
        eprintln!(
            "[WARN] accept_invite: failed to delete used invitation token -> {:?}",
            e
        );
    }

    let invite_request: InviteRequest = serde_json::from_str(&invite_data).map_err(|e| {
        ApiError::internal("accept_invite: deserializing cached invitation payload", e)
    })?;

    let hashed_password = bcrypt::hash(&accept_request.password, bcrypt::DEFAULT_COST)
        .map_err(|e| ApiError::internal("accept_invite: hashing password", e))?;

    let new_user = UserInsertable {
        first_name: Some(invite_request.first_name),
        last_name: Some(invite_request.last_name),
        middle_name: invite_request.middle_name,
        email_id: invite_request.email.clone(),
        mobile_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        password_hash: Some(hashed_password),
        is_root: invite_request.is_root,
        is_active: true,
    };

    insert_into(user)
        .values(&new_user)
        .execute(&mut conn)
        .map_err(|e| {
            ApiError::internal(
                &format!("accept_invite: inserting new user '{}'", invite_request.email),
                e,
            )
        })?;

    Ok(Json(
        "Invitation accepted, user registered successfully".to_string(),
    ))
}

#[openapi]
#[get("/accessible-apps")]
pub fn get_accessible_apps(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    groups: GroupMemberships,
) -> Result<Json<Vec<AccessibleApp>>, ApiError> {
    use crate::models::schema::schema::app::dsl as app_dsl;
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = get_conn(rdb, "get_accessible_apps")?;

    let apps_with_groups = app_dsl::app
        .left_join(group_dsl::group.on(group_dsl::id.nullable().eq(app_dsl::group_id)))
        .select((
            app_dsl::name,
            app_dsl::logo_url,
            app_dsl::allow_registration,
            app_dsl::tnc_link,
            app_dsl::app_url_dev,
            app_dsl::app_url_stage,
            app_dsl::app_url_prod,
            app_dsl::description,
            app_dsl::auth_redirection_path,
            app_dsl::web_interface,
            group_dsl::identifier.nullable(),
        ))
        .load::<(
            String,
            Option<String>,
            bool,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
            Option<String>,
        )>(&mut conn)
        .map_err(|e| ApiError::internal("get_accessible_apps: loading apps with group info", e))?;

    let user_groups: Vec<String> = groups.0;

    let accessible_apps: Vec<AccessibleApp> = apps_with_groups
        .into_iter()
        .filter_map(
            |(
                app_name,
                app_logo,
                app_allow_reg,
                app_tnc_link,
                app_dev_url,
                app_stage_url,
                app_prod_url,
                app_description,
                redirection_path,
                has_web_interface,
                group_identifier,
            )| {
                if group_identifier.is_none() || user_groups.contains(&group_identifier.unwrap()) {
                    Some(AccessibleApp {
                        name: app_name,
                        logo_url: app_logo,
                        allow_registration: app_allow_reg,
                        tnc_link: app_tnc_link,
                        description: app_description,
                        app_url_dev: app_dev_url,
                        app_url_stage: app_stage_url,
                        app_url_prod: app_prod_url,
                        redirection_path,
                        has_web_interface,
                    })
                } else {
                    None
                }
            },
        )
        .collect();

    Ok(Json(accessible_apps))
}

#[openapi()]
#[post("/generate-app-tokens/<app_id>")]
pub fn generate_app_tokens(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
    app_id: String,
    claims: Claims,
    groups: GroupMemberships,
) -> Result<Json<LoginResponse>, ApiError> {
    let mut conn = get_conn(rdb, "generate_app_tokens")?;
    let mut cache_connection = get_cache_conn(cache_pool, "generate_app_tokens")?;

    let has_access = user_has_access_to_app(&mut conn, &app_id, &groups.0).map_err(|e| {
        ApiError::internal(
            &format!("generate_app_tokens: checking access to app '{}'", app_id),
            e,
        )
    })?;

    if !has_access {
        return Err(ApiError::forbidden(&format!(
            "generate_app_tokens: user '{}' does not have access to app '{}'",
            claims.sub, app_id
        )));
    }

    let access_token = create_jwt(
        &claims.sub,
        &claims.user_id,
        "access",
        &claims.first_name,
        &claims.last_name,
        &claims.middle_name,
        &Some(app_id.clone()),
    )?;
    let refresh_token = create_jwt(
        &claims.sub,
        &claims.user_id,
        "refresh",
        &claims.first_name,
        &claims.last_name,
        &claims.middle_name,
        &Some(app_id.clone()),
    )?;

    let session_data = json!({
        "user_id": claims.user_id,
        "app_id": app_id,
    });
    let _: () = cache_connection
        .set_ex(refresh_token.clone(), session_data.to_string(), 3600)
        .map_err(|e| {
            ApiError::internal(
                &format!("generate_app_tokens: caching session for app '{}'", app_id),
                e,
            )
        })?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
    }))
}

#[openapi]
#[post("/create_or_update_app", data = "<app_request>")]
pub async fn create_or_update_app(
    app_request: Json<CreateOrUpdateAppRequest>,
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    _claims: APIClaims,
) -> Result<status::Created<Json<MessageResponse>>, ApiError> {
    use crate::models::schema::schema::app::dsl as app_dsl;

    let mut conn = get_conn(rdb, "create_or_update_app")?;

    let existing_app = app_dsl::app
        .filter(app_dsl::client_id.eq(&app_request.client_id))
        .first::<App>(&mut conn)
        .optional()
        .map_err(|e| {
            ApiError::internal(
                &format!(
                    "create_or_update_app: looking up app with client_id '{}'",
                    app_request.client_id
                ),
                e,
            )
        })?;

    if let Some(app) = existing_app {
        diesel::update(app_dsl::app.filter(app_dsl::id.eq(app.id)))
            .set((
                app_request.name.as_ref().map(|name| app_dsl::name.eq(name)),
                app_request
                    .logo_url
                    .as_ref()
                    .map(|url| app_dsl::logo_url.eq(url)),
                app_request
                    .disabled
                    .map(|disabled| app_dsl::disabled.eq(disabled)),
                app_request
                    .app_url_dev
                    .as_ref()
                    .map(|url| app_dsl::app_url_dev.eq(url)),
                app_request
                    .app_url_stage
                    .as_ref()
                    .map(|url| app_dsl::app_url_stage.eq(url)),
                app_request
                    .app_url_prod
                    .as_ref()
                    .map(|url| app_dsl::app_url_prod.eq(url)),
                app_request
                    .group_id
                    .map(|group| app_dsl::group_id.eq(group)),
                app_request
                    .tnc_link
                    .as_ref()
                    .map(|link| app_dsl::tnc_link.eq(link)),
                app_request
                    .allow_registration
                    .map(|allow| app_dsl::allow_registration.eq(allow)),
                app_request
                    .description
                    .as_ref()
                    .map(|desc| app_dsl::description.eq(desc)),
                app_request
                    .auth_redirection_path
                    .as_ref()
                    .map(|path| app_dsl::auth_redirection_path.eq(path)),
                app_request
                    .web_interface
                    .map(|web| app_dsl::web_interface.eq(web)),
            ))
            .execute(&mut conn)
            .map_err(|e| {
                ApiError::internal(
                    &format!("create_or_update_app: updating app id={}", app.id),
                    e,
                )
            })?;

        Ok(status::Created::new("/app").body(Json(MessageResponse {
            message: "App updated successfully".to_string(),
        })))
    } else {
        let new_app = AppInsertable {
            client_id: app_request.client_id.clone(),
            name: app_request.name.clone().unwrap_or_default(),
            logo_url: app_request.logo_url.clone(),
            disabled: app_request.disabled.unwrap_or(false),
            app_url_dev: app_request.app_url_dev.clone(),
            app_url_stage: app_request.app_url_stage.clone(),
            app_url_prod: app_request.app_url_prod.clone(),
            group_id: app_request.group_id,
            tnc_link: app_request.tnc_link.clone(),
            allow_registration: app_request.allow_registration.unwrap_or(false),
            description: app_request.description.clone(),
            auth_redirection_path: app_request.auth_redirection_path.clone(),
            web_interface: app_request.web_interface.unwrap_or(false),
        };

        diesel::insert_into(app_dsl::app)
            .values(&new_app)
            .execute(&mut conn)
            .map_err(|e| {
                ApiError::internal(
                    &format!(
                        "create_or_update_app: creating app with client_id '{}'",
                        app_request.client_id
                    ),
                    e,
                )
            })?;

        Ok(status::Created::new("/app").body(Json(MessageResponse {
            message: "App created successfully".to_string(),
        })))
    }
}

#[openapi()]
#[get("/is_member/<group_param>")]
pub fn is_member(
    group_param: String,
    groups: GroupMemberships,
    groups_owned: GroupOwnerships,
) -> Json<IsMemberResponse> {
    let is_member = groups.0.contains(&group_param);
    let is_owner = groups_owned.0.contains(&group_param);

    Json(IsMemberResponse {
        is_member,
        is_owner,
    })
}

// ── Libtrust kid computation ─────────────────────────────────────────────────

fn compute_libtrust_kid(signing_key: &SigningKey) -> Result<String, ApiError> {
    let pub_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| ApiError::internal("compute_libtrust_kid: encoding public key to DER", e))?;

    // SHA256 of the DER bytes, take first 30 bytes (240 bits)
    let digest = Sha256::digest(pub_der.as_bytes());
    let truncated = &digest[..30];

    // Base32-encode (no padding) → 48 chars → split into 12 groups of 4
    let b32 = base32::encode(Alphabet::RFC4648 { padding: false }, truncated);
    Ok(b32
        .chars()
        .collect::<Vec<char>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(":"))
}

// ── Core token generation function ───────────────────────────────────────────
fn generate_docker_token(
    service: &str,
    scope: Option<&str>,
    account: &str,
) -> Result<DockerTokenResponse, ApiError> {
    let pem = env::var("DOCKER_REGISTRY_PRIVATE_KEY").map_err(|e| {
        ApiError::internal("generate_docker_token: reading DOCKER_REGISTRY_PRIVATE_KEY env var", e)
    })?;

    let signing_key = if pem.contains("BEGIN EC PRIVATE KEY") {
        SigningKey::from_sec1_pem(&pem)
            .map_err(|e| ApiError::internal("generate_docker_token: parsing SEC1 PEM private key", e))
    } else {
        SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| ApiError::internal("generate_docker_token: parsing PKCS8 PEM private key", e))
    }?;

    let kid = compute_libtrust_kid(&signing_key)?;

    // Convert to PKCS#8 PEM in memory so jsonwebtoken can consume it
    // regardless of what format the original key was in
    let pkcs8_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| ApiError::internal("generate_docker_token: re-encoding key as PKCS8 PEM", e))?;

    let encoding_key = EncodingKey::from_ec_pem(pkcs8_pem.as_bytes())
        .map_err(|e| ApiError::internal("generate_docker_token: building EC encoding key", e))?;

    let access: Vec<DockerAccess> = scope
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|s| {
            let parts: Vec<&str> = s.splitn(3, ':').collect();
            if parts.len() == 3 {
                let actions = parts[2]
                    .split(',')
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect();
                Some(DockerAccess {
                    resource_type: parts[0].to_string(),
                    name: parts[1].to_string(),
                    actions,
                })
            } else {
                eprintln!(
                    "[WARN] generate_docker_token: skipping malformed scope segment '{}'",
                    s
                );
                None
            }
        })
        .collect();

    let now = Utc::now().timestamp() as usize;
    let jti: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let issuer = env::var("DOCKER_TOKEN_ISSUER").unwrap_or_else(|_| {
        eprintln!("[WARN] generate_docker_token: DOCKER_TOKEN_ISSUER not set, using default");
        "my-auth-server".to_string()
    });

    let claims = DockerTokenClaims {
        iss: issuer,
        sub: account.to_string(),
        aud: service.to_string(),
        exp: now + 300,
        nbf: now.saturating_sub(10),
        iat: now,
        jti,
        access,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid);
    header.typ = Some("JWT".to_string());

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| ApiError::internal("generate_docker_token: encoding JWT", e))?;

    Ok(DockerTokenResponse {
        token,
        expires_in: 300,
    })
}

#[openapi()]
#[get("/docker-token?<service>&<scope>&<account>")]
pub fn get_docker_token(
    auth: BasicAuth,
    service: String,
    scope: Option<String>,
    account: Option<String>,
) -> Result<Json<DockerTokenResponse>, ApiError> {
    // Use authenticated subject, fall back to account param, then anonymous
    let subject = if !auth.subject.is_empty() {
        auth.subject
    } else {
        account.unwrap_or_default()
    };

    let response = generate_docker_token(&service, scope.as_deref(), &subject)?;
    Ok(Json(response))
}