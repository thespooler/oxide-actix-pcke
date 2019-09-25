use oxide_auth_actix::{OAuthRequest,OAuthResponse};
use oxide_auth::{ 
    code_grant::extensions::Pkce,
    endpoint::{Endpoint,OwnerConsent,OwnerSolicitor},
    frontends::simple::endpoint::{Error, Generic,Vacant},
    frontends::simple::extensions::{AddonList,Extended},
    primitives::prelude::{AuthMap, Client, ClientMap, PreGrant, RandomGenerator, TokenMap},
};

pub struct PkceSetup {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: TokenMap<RandomGenerator>,
    auth_token: String,
    verifier: String,
    sha256_challenge: String,
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