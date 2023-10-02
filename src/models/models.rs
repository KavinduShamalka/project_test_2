use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
// use chrono::prelude::*;

//User structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub email: String,
    pub password: String,
}

//User login schema
#[derive(Debug, Deserialize)]
pub struct LoginSchema {
    pub email: String,
    pub password: String,
}

//Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse{
    pub status: bool,
    pub message: String,
}

//Token claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

//Todo structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Todos {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "_uid", skip_serializing_if = "Option::is_none")]
    pub uid: Option<ObjectId>,
    pub description: String,
    #[serde(rename = "_createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

//UpdateTodo structure
#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateTodo {
    pub description: String,
}