mod pkcetest;

use actix::{Actor,Addr};
use actix_web::{App, HttpRequest, HttpServer, web};
use futures::future::Future;
use log::info;
use oxide_auth_actix::{Authorize,OAuthOperation,OAuthRequest,OAuthResource,OAuthResponse,Refresh,Resource,Token,WebError};
use pkcetest::{PkceSetup,Extras};

static DENY_TEXT: &str = "<html>
<h1>NO!!!</h1>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8653/oauth/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>";

fn create_session() -> Result<OAuthResponse, WebError> {
    info!("create_session!!");
    Ok(OAuthResponse::ok().content_type("text/plain")?.body("Logged in"))
}

fn main() {
    std::env::set_var("RUST_LOG", "actix_shopper=info,actix_server=info,actix_web=info");

    let sys = actix::System::new("HttpServerClient");

    let mut pkce_setup = PkceSetup::new();
    let endpoint = pkce_setup.allowing_endpoint();
    let pkce_agent = pkce_setup.start();

    HttpServer::new(move || {
        App::new()
            .data(pkce_agent)
            .service(web::scope("/oauth/")
                .service(
                    web::resource("/authorize")
                        .route(web::get().to_async(
                            |(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                                // GET requests should not mutate server state and are extremely
                                // vulnerable accidental repetition as well as Cross-Site Request
                                // Forgery (CSRF).
                                state
                                    .send(Authorize(req).wrap(Extras::AuthGet))
                                    .map_err(WebError::from)
                            },
                        ))
                        .route(web::post().to_async(
                            |(r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                                // Some authentication should be performed here in production cases
                                state
                                    .send(
                                        Authorize(req)
                                            .wrap(Extras::AuthPost(r.query_string().to_owned())),
                                    )
                                    .map_err(WebError::from)
                            },
                        )),
                )
                .route(
                    "/token",
                    web::post().to_async(|(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                        state
                            .send(Token(req).wrap(Extras::Nothing))
                            .map_err(WebError::from)
                    }),
                )
                .route(
                    "/refresh",
                    web::post().to_async(|(req, state): (OAuthRequest, web::Data<Addr<PkceSetup>>)| {
                        state
                            .send(Refresh(req).wrap(Extras::Nothing))
                            .map_err(WebError::from)
                    }),
                )
                .route("/endpoint",
                    web::get().to_async(|(req, state): (OAuthResource, web::Data<Addr<PkceSetup>>)| {
                        state
                            .send(Resource(req.into_request()).wrap(Extras::Nothing))
                            .map_err(WebError::from)
                            .and_then(|res| match res {
                                Ok(_grant) => create_session(), //actix_files::Files::new("/", "./web/dist").index_file("index.html"),
                                Err(Ok(response)) => Ok(response.body(DENY_TEXT)),
                                Err(Err(e)) => Err(e.into()),
                            })
                    })
                )
            )
    })
    .bind("0.0.0.0:8081")
    .expect("Failed to bind to socket")
    .start();

    sys.run().expect("Failed to start actors loop");
}
