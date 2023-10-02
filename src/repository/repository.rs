use std::env;
extern crate dotenv;
use actix_web::{
    HttpResponse, cookie::Cookie,
    cookie::time::Duration as ActixWebDuration,
};
use chrono::{Utc, Duration};
use dotenv::dotenv;

use futures::StreamExt;
use jsonwebtoken::{encode, Header, EncodingKey, decode, DecodingKey, Algorithm, Validation};
use mongodb::{Collection, Client, bson::{doc, oid::ObjectId}};
use serde_json::json;


use crate::models::models::{User, LoginSchema, ErrorResponse, TokenClaims, Todos, UpdateTodo};


//Mongodb collections
#[derive(Debug, Clone)]
pub struct MongoRepo {
    user: Collection<User>,
    todo: Collection<Todos>
}

//Implementation of mongodb repo
impl MongoRepo {

    //Initiatize database connection
    pub async fn init() -> Self {

        dotenv().ok();
        let url = match env::var("MONGOURI"){
            Ok(url) => url.to_string(),
            Err(_) => format!("Error loading env variable")
        };

        let client = Client::with_uri_str(url).await.unwrap();
        let db = client.database("todo_api");
        let user = db.collection("user");
        let todo = db.collection("todo");


        MongoRepo {
            user,
            todo
        }
    }

    //handler to validate the user's token
    pub async fn token_validation(&self, token: &str) -> Result<Option<User>, HttpResponse>{

        let secret_key = "secret".to_owned();
        
        let var = secret_key;
        let key = var.as_bytes();
        let decode = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(key),
            &Validation::new(Algorithm::HS256),
        );
    
        println!("decode: {:?}", decode);
    
        match decode {
            Ok(decoded) => {
    
                let id = decoded.claims.sub;
    
                let bson_id = ObjectId::parse_str(id).unwrap();
    
                let user = self
                    .user
                    .find_one( doc! {"_id" : bson_id }, None)
                    .await.ok()
                    .expect("Error finding");
            
                Ok(user)
    
            }
            Err(_) => Err(  
                HttpResponse::BadRequest().json(ErrorResponse{
                    status: false,
                    message: "Invalid token".to_owned()
                }))
            }
    }
    

    //found by email
    pub async fn found_by_email(&self, email: String) -> String {

        let filter_email = doc! { "email" : email};
    
        let check_email = self
            .user
            .find_one(filter_email, None)
            .await.ok()
            .expect("Error finding email");
                
    
        match check_email {
            Some(user) => user.email,
            None => "No user found".to_string()
        }
    
    }

    //found user by email and password
    pub async fn validate_email_and_password(&self, email: &String, password: &String) -> Result<Option<User>, ErrorResponse> {
            
        let user = match self
            .user
            .find_one( doc! {"email" : email, "password" : password}, None)
            .await.ok() {
                Some(user) => Ok(user),
                None => {Err(ErrorResponse {
                    status: false,
                    message: "Invalid email or password".to_string()
                })}
            };

        user

    }

    //finding product
    pub async fn finding_todo(&self, token: &str, todo_id: ObjectId) -> Result<Option<Todos>, ErrorResponse> {

        match self.token_validation(token).await.unwrap() {
            Some(user) => {
                    
                let user_id = user.id.unwrap();
            
                let product = self
                    .todo
                    .find_one( doc! {
                        "_id" : todo_id,
                        "_uid" : user_id
                    }, None)
                .await.ok()
                .expect("Error finding product");
            
                Ok(product)
            },
            None => Err(ErrorResponse{
                status: false,
                message: "User not found".to_string(),
            })
        }
    }

    //User registration
    pub async fn user_registartion(&self, user: User) -> Result<HttpResponse, ErrorResponse> {

        let email = self.found_by_email(user.email.clone()).await;

        let new_email = user.email.clone();

        if email == new_email {
            Err(
                ErrorResponse{
                    status: false,
                    message: "Email already exists ==> Give new email".to_owned()
                }
            )
        } else {

            let doc = User {
                id: None,
                name: user.name,
                email: user.email,
                password: user.password,
            };

            let registerd_user = self
                .user
                .insert_one(doc, None)
                .await.ok()
                .expect("Error creating user");

            Ok(HttpResponse::Ok().json(json!({"status" : "success" , "message" : registerd_user})))
        }
    }


    //User Login
    pub async fn login_handler(&self, login: LoginSchema) -> Result<HttpResponse, ErrorResponse> {

        match self.validate_email_and_password(&login.email, &login.password).await.unwrap() {

            Some(user) => {

                let jwt_secret = "secret".to_owned();

                let id = user.id.unwrap();  //Convert Option<ObjectId> to ObjectId using unwrap()

                let now = Utc::now();
                let iat = now.timestamp() as usize;
                
                let exp = (now + Duration::minutes(1)).timestamp() as usize;
                let claims: TokenClaims = TokenClaims {
                    sub: id.to_string(),
                    exp,
                    iat,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(jwt_secret.as_ref()),
                )
                .unwrap();

                let cookie = Cookie::build("token", token.to_owned())
                    .path("/")
                    .max_age(ActixWebDuration::new(60 * 60, 0))
                    .http_only(true)
                    .finish();
                
                Ok(HttpResponse::Ok()
                    .cookie(cookie)
                    .json(json!({"status" :  "success", "token": token})))
            },

            None => {
                Err(ErrorResponse{
                    status: false,
                    message: "Invalid username or password".to_owned()
                })
            }
        }

    }

    //Add todo handler
    pub async fn add_todo_handler(&self, todo: Todos, token: &str) -> Result<HttpResponse, ErrorResponse> {

        match self.token_validation(token).await.unwrap(){

            Some(user) => {

                let id = user.id.unwrap();

                let new_todo = Todos {
                    id: None,
                    uid: Some(id),
                    created_at: Some(Utc::now()),
                    description: todo.description,
                };

                let insert_todo = self
                    .todo
                    .insert_one(new_todo, None)
                    .await
                    .ok()
                    .expect("Error inserting product");

                Ok(HttpResponse::Ok().json(json!({"status" : "success" , "Inserted todo" : insert_todo})))
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "No user found".to_string(),
                })               
            }
        }
    }

    //Update todo
    pub async fn update_todo_handler(&self, token: &str, todo: UpdateTodo, todo_id: String) -> Result<HttpResponse, ErrorResponse> {

        match self.token_validation(token).await.unwrap() {

            Some(_) => {

                let todoid = ObjectId::parse_str(todo_id).unwrap();

                match self.finding_todo(&token, todoid).await.unwrap() {

                    Some(_) => {

                        let filter = doc! {
                            "_id" : todoid
                        };


                        let update_todo = doc! {
                            "$set":
                                {
                                    "description" : todo.description,
                                },
                        };

                        let updated_todo = self
                            .todo
                            .update_one(filter, update_todo, None)
                            .await
                            .ok()
                            .expect("Error updating product");

                        Ok(HttpResponse::Ok().json(json!({"status" : "success" , "message" : updated_todo})))

                    },
                    None => {
                        return Err(
                            ErrorResponse{
                                status: false,
                                message: "Product not found".to_owned()
                            }
                        )
                    }
                }

            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })              
            }
        }
    }

    //Delete todo
    pub async fn delete_todo(&self, token: &str, todo_id: String) -> Result<HttpResponse, ErrorResponse> {

        match self.token_validation(token).await.unwrap() {
    
            Some(user) => {
    
                let id = ObjectId::parse_str(todo_id).unwrap();
    
                match self.finding_todo(&token, id).await.unwrap() {
    
                    Some(todo) => {
    
                        let filter = doc! {
                            "_id" : todo.id.unwrap(),
                            "_uid" :user.id.unwrap()
                        };
    
                        let deleted_todo = self
                            .todo
                            .delete_one(filter, None)
                            .await
                            .ok()
                            .expect("Error deleting product");
    
                        Ok(HttpResponse::Ok().json(json!({"status" : "success" , "message" : deleted_todo})))
                    },
                    None => {
                        return Err(ErrorResponse {
                            message: "Product Not found".to_owned(),
                            status: false
                        })                       
                    }
                }
            },
            None => Err(ErrorResponse {
                        status: false,
                        message: "No user found.".to_string(),
                    }  
            )
        }
    }

    //Get all products
    pub async fn todo_list(&self, token: &str) -> Result<HttpResponse, ErrorResponse> {

        match self.token_validation(token).await.unwrap(){

            Some(user) => {

                let user_id = user.id.unwrap();

                let doc = doc! {
                    "_uid" : user_id
                };

                let mut todo_list = self
                    .todo
                    .find(doc, None)
                    .await
                    .ok()
                    .expect("Error finding todos");

                let mut todo_vec = Vec::new();

                while let Some(doc) = todo_list.next().await {

                    match doc {
                        Ok(todo) => {
                            todo_vec.push(todo)
                        },
                        Err(err) => {
                            
                            eprintln!("Error finding todo: {:?}", err)
                        },
                    }
                }

                Ok(HttpResponse::Ok().json(json!({"status" : "success", "result" : todo_vec})))
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })
            }
        }
    }



}

