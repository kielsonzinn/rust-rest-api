use actix_web::{post, get, web, App, HttpResponse, HttpRequest, HttpServer, Responder};
use bcrypt::{verify, DEFAULT_COST, hash};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use jsonwebtoken::{encode, decode, DecodingKey, EncodingKey, Validation, Header};
use chrono::{Utc, Duration};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn create_jwt(user_id: &str) -> String {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set");
    let expiration = (Utc::now() + Duration::days(1)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[post("/register")]
async fn register(db_pool: web::Data<sqlx::PgPool>, reg_request: web::Json<RegisterRequest>) -> impl Responder {
    let RegisterRequest { username, password } = reg_request.into_inner();

    let hashed_password = hash(&password, DEFAULT_COST).unwrap();

    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        username,
        hashed_password
    )
    .execute(db_pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().finish(),
        Err(e) => {
            println!("Error occurred while registering user: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/login")]
async fn login(db_pool: web::Data<sqlx::PgPool>, login_request: web::Json<LoginRequest>) -> impl Responder {
    let LoginRequest { username, password } = login_request.into_inner();

    let result = sqlx::query!("SELECT id, password FROM users WHERE username = $1", username)
        .fetch_one(db_pool.get_ref())
        .await;

    match result {
        Ok(record) => {
            if verify(&password, &record.password).unwrap_or(false) {
                let token = create_jwt(&record.id.to_string());
                println!("Login successful for user: {}", username);
                HttpResponse::Ok().json(json!({ "token": token }))
            } else {
                println!("Invalid password for user: {}", username);
                HttpResponse::Unauthorized().finish()
            }
        }
        Err(e) => {
            println!("Error occurred while fetching user: {:?}", e);
            HttpResponse::Unauthorized().finish()
        }
    }
}

#[get("/me")]
async fn me(req: HttpRequest, db_pool: web::Data<sqlx::PgPool>) -> impl Responder {
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_header) = auth_header {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let secret = env::var("JWT_SECRET").expect("JWT_SECRET is not set");
                let token_data = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(secret.as_bytes()),
                    &Validation::default(),
                );

                match token_data {
                    Ok(data) => {
                        let user_id = data.claims.sub.parse::<i32>().unwrap();
                        let result = sqlx::query!(
                            "SELECT username FROM users WHERE id = $1",
                            user_id
                        )
                        .fetch_one(db_pool.get_ref())
                        .await;

                        match result {
                            Ok(record) => HttpResponse::Ok().json(json!({ "username": record.username })),
                            Err(_) => HttpResponse::Unauthorized().finish(),
                        }
                    }
                    Err(_) => HttpResponse::Unauthorized().finish(),
                }
            } else {
                HttpResponse::Unauthorized().finish()
            }
        } else {
            HttpResponse::Unauthorized().finish()
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[derive(sqlx::FromRow, Serialize, Debug)]
struct User {
    id: i32,
    username: String,
}

#[get("/users")]
async fn get_users(db_pool: web::Data<sqlx::PgPool>) -> impl Responder {
    let result = sqlx::query_as::<_, User>("SELECT id, username FROM users ORDER BY id")
        .fetch_one(db_pool.get_ref())
        .await;

    match result {
        Ok(user) => {
            log::info!("User found: {:?}", user);
            HttpResponse::Ok().json(user)
        }
        Err(e) => {
            log::error!("Error occurred: {:?}", e);
            HttpResponse::NoContent().finish()
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set");

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .service(login)
            .service(me)
            .service(get_users)
            .service(register)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
