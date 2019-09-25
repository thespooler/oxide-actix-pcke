mod pkcetest;

use actix_web::{App, HttpServer};

fn main() {
    std::env::set_var("RUST_LOG", "actix_shopper=info,actix_server=info,actix_web=info");

    let sys = actix::System::new("HttpServerClient");

    let mut pkce_setup = pkcetest::PkceSetup::new();

    let x = pkce_setup.allowing_endpoint();

    HttpServer::new(move || {
        App::new()
    })
    .bind("0.0.0.0:8081")
    .expect("Failed to bind to socket")
    .start();

    sys.run().expect("Failed to start actors loop");
}
