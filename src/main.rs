mod pkcetest;

use actix::{Actor,Addr};
use actix_web::{App, HttpRequest, HttpServer, web};
use log::info;
use oxide_auth_actix::{Authorize,OAuthOperation,OAuthRequest,OAuthResource,OAuthResponse,Refresh,Resource,Token,WebError};
use pkcetest::{PkceSetup,Extras};

static DENY_TEXT: &str = "<html>
<h1>NO!!!</h1>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8081/oauth/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>";

fn create_session() -> Result<OAuthResponse, WebError> {
    info!("create_session!!");
    Ok(OAuthResponse::ok().content_type("text/plain")?.body("Logged in"))
}

fn main() {
    std::env::set_var("RUST_LOG", "actix_shopper=info,actix_server=info,actix_web=info");
    env_logger::init();

    let sys = actix::System::new("HttpServerClient");

    let pkce_agent = PkceSetup::new().start();

    HttpServer::new(move || {
        App::new()
            .data(pkce_agent.clone())
            .service(web::scope("/oauth/")
                .service(
                    web::resource("/authorize")
                        .route(web::get().to(
                            |(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                                state.send(Authorize(req).wrap(Extras::AuthGet))
                            },
                        ))
                        .route(web::post().to(
                            |(r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                                state.send(Authorize(req).wrap(Extras::AuthPost(r.query_string().to_owned())))
                            },
                        ))
                )
                .route(
                    "/token",
                    web::post().to(|(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                        state.send(Token(req).wrap(Extras::Nothing))
                    }),
                )
                .route(
                    "/refresh",
                    web::post().to(|(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                        state.send(Refresh(req).wrap(Extras::Nothing))
                    }),
                )
            )
            .route("/resource", web::get().to(resource))
            .service(actix_files::Files::new("/", "./static").index_file("index.html"))
    })
    .bind("0.0.0.0:8081")
    .expect("Failed to bind to socket")
    .run();

    sys.run().expect("Failed to start actors loop");
}

async fn resource(req: OAuthResource, state: web::Data<Addr<PkceSetup>>) -> Result<OAuthResponse, WebError> {
    let resource = state.send(Resource(req.into_request()).wrap(Extras::Nothing)).await?;
    match resource {
        Ok(_grant) => create_session(), //actix_files::Files::new("/", "./web/dist").index_file("index.html"),
        Err(Ok(response)) => Ok(response.body(DENY_TEXT)),
        Err(Err(e)) => Err(e.into()),
    }
}