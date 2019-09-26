use actix::{Actor,Context,Handler};
use oxide_auth_actix::{OAuthMessage,OAuthOperation,OAuthRequest,OAuthResponse,WebError};
use oxide_auth::{ 
    code_grant::extensions::Pkce,
    endpoint::{Endpoint,OwnerConsent,OwnerSolicitor},
    frontends::simple::endpoint::{Error,ErrorInto,FnSolicitor,Generic,Vacant},
    frontends::simple::extensions::{AddonList,Extended},
    primitives::prelude::{AuthMap, Client, ClientMap, PreGrant, RandomGenerator, TokenMap},
};

pub(crate) enum Extras {
    AuthGet,
    AuthPost(String),
    Nothing,
}

pub struct PkceSetup {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: TokenMap<RandomGenerator>,
    auth_token: String,
    verifier: String,
    sha256_challenge: String,
}

impl Actor for PkceSetup {
    type Context = Context<Self>;
}

impl PkceSetup {
    pub fn new() -> PkceSetup {
        let client = Client::public("EXAMPLE_CLIENT_ID",
            "EXAMPLE_REDIRECT_URI".parse().unwrap(),
            "EXAMPLE_SCOPE".parse().unwrap());

        let mut registrar = ClientMap::new();
        registrar.register_client(client);

        let token = "ExampleAuthorizationToken".to_string();
        let authorizer = AuthMap::new(RandomGenerator::new(16));
        let issuer = TokenMap::new(RandomGenerator::new(16));

        PkceSetup {
            registrar: registrar,
            authorizer: authorizer,
            issuer: issuer,
            auth_token: token,
            // The following are from https://tools.ietf.org/html/rfc7636#page-18
            sha256_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        }
    }
    
    pub fn allowing_endpoint(&mut self) -> impl Endpoint<OAuthRequest, Error=Error<OAuthRequest>> + '_ {
        let pkce_extension = Pkce::required();

        let mut extensions = AddonList::new();
        extensions.push_code(pkce_extension);

        let endpoint = Generic {
            registrar: &self.registrar,
            authorizer: &mut self.authorizer,
            issuer: &mut self.issuer,
            scopes: Vacant,
            solicitor: Allow("EXAMPLE_OWNER_ID".to_string()),
            response: Vacant,
        };

        Extended::extend_with(endpoint, extensions)
    }

    pub fn with_solicitor<'a, S>(
        &'a mut self,
        solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.authorizer,
            registrar: &self.registrar,
            issuer: &mut self.issuer,
            solicitor,
            scopes: Vacant,
            response: OAuthResponse::ok,
        })
    }
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for PkceSetup
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::AuthGet => {
                let solicitor = FnSolicitor(move |req: &mut OAuthRequest, pre_grant: &PreGrant| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok().content_type("text/html").unwrap().body(
                            &consent_page_html("/oauth/authorize".into(), pre_grant),
                        ),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: &PreGrant| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(Generic {
                authorizer: &mut self.authorizer,
                registrar: &self.registrar,
                issuer: &mut self.issuer,
                solicitor: Vacant,
                scopes: Vacant,
                response: OAuthResponse::ok,
            }),
        }
    }
}

struct Allow(String);
struct Deny;

impl OwnerSolicitor<OAuthRequest> for Allow {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: &PreGrant)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl OwnerSolicitor<OAuthRequest> for Deny {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: &PreGrant)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Denied
    }
}

impl<'l> OwnerSolicitor<OAuthRequest> for &'l Allow {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: &PreGrant)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl<'l> OwnerSolicitor<OAuthRequest> for &'l Deny {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: &PreGrant)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Denied
    }
}

pub fn consent_page_html(route: &str, grant: &PreGrant) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?response_type=code&client_id={3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?response_type=code&client_id={3:}&deny=true\">
</form>
</html>"
        };
    }
    
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        grant.client_id,
        &route)
}