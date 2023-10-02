use actix_web::{get, Responder, HttpResponse, web::{Data, Json, self}, post, HttpRequest, put, delete};
use serde_json::json;

use crate::{repository::repository::MongoRepo, models::models::{User, LoginSchema, Todos, UpdateTodo}};

//Token
pub fn token(req: HttpRequest) -> String {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim().to_owned();

    token
}

#[get("/test")]
pub async fn test() -> impl Responder {
    const MESSAGE: &str = "Todo API";
    HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": MESSAGE}))
}

//Register user
#[post("/register")]
pub async fn register_user(db: Data<MongoRepo>, new_user: Json<User>) -> HttpResponse {

    let data = User {
        id: None,
        name: new_user.name.to_owned(),
        email: new_user.email.to_owned(),
        password: new_user.password.to_owned(),
    };

    match db.user_registartion(data).await {
        Ok(_) => HttpResponse::Ok().json(json!({"status" : "success", "message" : "Registration successfull"})),
        Err(error) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error}))
    }
}

//Login
#[post("/login")]
pub async fn user_login(data: Json<LoginSchema>, db: Data<MongoRepo>) -> HttpResponse {

    let user_data = db.login_handler(data.into_inner()).await;

    match user_data {
        Ok(response) => response,
        Err(error) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed" , "message" : error}))
    }

}

//create todo
#[post("/add/todo")]
pub async fn add_todo(data: Json<Todos>, db: Data<MongoRepo>, req: HttpRequest) -> HttpResponse {

  let token = token(req);

  let todo = Todos {
    id: None,
    uid: None,
    description: data.description.to_owned(),
    created_at: None
  };

  match db.add_todo_handler(todo, token.as_str()).await {
    Ok(todo) => todo,
    Err(err) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : err})),
  }

}


//Update
#[put("/update/todo/{id}")]
pub async fn update_todo(req: HttpRequest, data: Json<UpdateTodo>, id: web::Path<String>, db: Data<MongoRepo>) -> HttpResponse {

    let token = token(req);

    let todo_id = id.into_inner();

    let update_todo = UpdateTodo {

        description: data.description.clone(),

    };

    match db.update_todo_handler(token.as_str(), update_todo, todo_id).await {
        Ok(updated_todo) => updated_todo,
        Err(err) => HttpResponse::Ok().json(err),
    }

}

//Delete
#[delete("/delete/todo/{id}")]
pub async fn delete_todo(req: HttpRequest, db: Data<MongoRepo>, id: web::Path<String>) -> HttpResponse {

    let todo_id = id.into_inner();

    let token = token(req);

    match db.delete_todo(token.as_str(), todo_id).await {
        Ok(delete_todo) => delete_todo,
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
    }
}

//Get all todos
//Find all products
#[get("/all/todos")]
pub async fn all_todos(req: HttpRequest, db: Data<MongoRepo>) -> HttpResponse {

    let token = token(req);

    match db.todo_list(token.as_str()).await {
        Ok(result) => result,
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),        
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(test)
        .service(register_user)
        .service(user_login)
        .service(add_todo)
        .service(update_todo)
        .service(delete_todo)
        .service(all_todos);
}