mod pages;
mod pkcetest;

use actix::{Actor,Addr};
use actix_web::{
    error::Result,
    web::{self, Data}, 
    App, HttpRequest, HttpServer, middleware::{Logger, TrailingSlash, NormalizePath},
};
use oxide_auth_actix::{Authorize,OAuthOperation,OAuthRequest,OAuthResource,OAuthResponse,Refresh,Resource,Token,WebError};
use pkcetest::{PkceSetup,Extras};
use sailfish::TemplateOnce;

fn get_protected_ressource() -> Result<OAuthResponse, WebError> {
    Ok(OAuthResponse::ok().content_type("text/plain")?.body("SECRET DATA"))
}

async fn get_authorize((req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)) -> Result<OAuthResponse, WebError> {
    state.send(Authorize(req).wrap(Extras::AuthGet)).await?
}

async fn post_authorize(
    (httpreq, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<PkceSetup>>)
) -> Result<OAuthResponse, WebError> {
    state.send(Authorize(req).wrap(Extras::AuthPost(httpreq.query_string().to_owned()))).await?
}

async fn post_token(
    (req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)
) -> Result<OAuthResponse, WebError> {
    state.send(Token(req).wrap(Extras::Nothing)).await?
}

async fn post_refresh(req: OAuthRequest, state: web::Data<Addr<PkceSetup>>) -> Result<OAuthResponse, WebError> {
    state.send(Refresh(req).wrap(Extras::Nothing)).await?
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let pkce_agent = PkceSetup::new().start();

    HttpServer::new(move || {
        App::new()
            .wrap(NormalizePath::new(TrailingSlash::Trim))
            .wrap(Logger::default())
            .app_data(Data::new(pkce_agent.clone()))
            .service(web::scope("/oauth")
                .service(
                    web::resource("/authorize")
                        .route(web::get().to(get_authorize))
                        .route(web::post().to(post_authorize))
                )
                .route("/token",web::post().to(post_token))
                .route("/refresh", web::post().to(post_refresh))
            )
            .route("/resource", web::get().to(resource))
            .service(actix_files::Files::new("/", "./static").index_file("index.html"))
    })
    .bind("0.0.0.0:8081")
    .expect("Failed to bind to socket")
    .run()
    .await
}

async fn resource(req: OAuthResource, state: web::Data<Addr<PkceSetup>>) -> Result<OAuthResponse, WebError> {
    let resource = state.send(Resource(req.into_request()).wrap(Extras::Nothing)).await?;
    match resource {
        Ok(_grant) => get_protected_ressource(),
        Err(Ok(response)) => Ok(response.body(&crate::pages::DenyPage {}.render_once().unwrap())),
        Err(Err(e)) => Err(e.into()),
    }
}