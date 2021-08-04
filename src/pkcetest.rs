use core::marker::PhantomData;
use actix::{Actor,Context,Handler};
use oxide_auth::{
    code_grant::extensions::Pkce,
    endpoint::{Authorizer,Endpoint,Extension,OAuthError,OwnerConsent,OwnerSolicitor,QueryParameter,Scopes,Solicitation,Template,WebRequest},
    frontends::simple::endpoint::{Error,FnSolicitor,Generic,Vacant},
    frontends::simple::extensions::{AddonList,Extended},
    primitives::prelude::*,
};
use oxide_auth_actix::{OAuthMessage,OAuthOperation,OAuthRequest,OAuthResponse,WebError};
use std::borrow::Cow;

pub(crate) enum Extras {
    AuthGet,
    AuthPost(String),
    Nothing,
}

pub struct PkceSetup {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: TokenMap<RandomGenerator>,
    scopes: Vec<Scope>
}

impl Actor for PkceSetup {
    type Context = Context<Self>;
}

impl PkceSetup {
    pub fn new() -> PkceSetup {
        let scope: Scope = "default-scope".parse().unwrap();
        let client = Client::public("LocalClient",
            "http://localhost:8081/".parse::<url::Url>().unwrap().into(),
            scope.clone());

        let mut registrar = ClientMap::new();
        registrar.register_client(client);

        let authorizer = AuthMap::new(RandomGenerator::new(16));
        let issuer = TokenMap::new(RandomGenerator::new(16));

        PkceSetup {
            registrar: registrar,
            authorizer: authorizer,
            issuer: issuer,
            scopes: vec![scope]
        }
    }
    
    pub fn allowing_endpoint<'a, S>(&'a mut self, solicitor: S) -> impl Endpoint<OAuthRequest, Error = Error<OAuthRequest>> + 'a
    where S: OwnerSolicitor<OAuthRequest> + 'static
    {
        let pkce_extension = Pkce::required();

        let mut extensions = AddonList::new();
        extensions.push_code(pkce_extension);

        let endpoint = Generic {
            registrar: &self.registrar,
            authorizer: &mut self.authorizer,
            issuer: &mut self.issuer,
            scopes: &mut self.scopes,
            solicitor: solicitor,
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
        ErrorInto::new(self.allowing_endpoint(solicitor))
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
                let solicitor = FnSolicitor(move |req: &mut OAuthRequest, solicitation: Solicitation| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok().content_type("text/html").unwrap().body(
                            &consent_page_html(req, "/oauth/authorize".into(), solicitation),
                        ),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(self.allowing_endpoint(Allow("LocalClient".to_string()))),
        }
    }
}

struct Allow(String);
struct Deny;

impl OwnerSolicitor<OAuthRequest> for Allow {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: Solicitation)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl OwnerSolicitor<OAuthRequest> for Deny {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: Solicitation)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Denied
    }
}

impl<'l> OwnerSolicitor<OAuthRequest> for &'l Allow {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: Solicitation)
        -> OwnerConsent<OAuthResponse>
    {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl<'l> OwnerSolicitor<OAuthRequest> for &'l Deny {
    fn check_consent(&mut self, _: &mut OAuthRequest, _: Solicitation)
        -> OwnerConsent<OAuthResponse> 
    {
        OwnerConsent::Denied
    }
}

pub fn consent_page_html(request: &OAuthRequest, route: &str, solicitation: Solicitation) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?response_type=code&client_id={3:}&state={5:}&code_challenge={6:}&code_challenge_method={7:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?response_type=code&client_id={3:}&deny=true\">
</form>
</html>"
        };
    }

    let query = request.query().unwrap();
    let state = query.unique_value("state").unwrap_or(Cow::Borrowed("")).to_string();
    let code_challenge = query.unique_value("code_challenge").unwrap_or(Cow::Borrowed("")).to_string();
    let code_challenge_method = query.unique_value("code_challenge_method").unwrap_or(Cow::Borrowed("")).to_string();
    let pre_grant = solicitation.pre_grant();

    format!(template!(), 
        pre_grant.client_id,
        pre_grant.redirect_uri,
        pre_grant.scope,
        pre_grant.client_id,
        &route,
        state,
        code_challenge,
        code_challenge_method)
}

pub(crate) struct ErrorInto<E, Error>(E, PhantomData<Error>);

impl<E, Error> ErrorInto<E, Error> {
    /// Create a new ErrorInto wrapping the supplied endpoint.
    pub fn new(endpoint: E) -> Self {
        ErrorInto(endpoint, PhantomData)
    }
}

impl<E, Error, W> Endpoint<W> for ErrorInto<E, Error>
where
    E: Endpoint<W>,
    E::Error: Into<Error>,
    W: WebRequest,
{
    type Error = Error;

    fn registrar(&self) -> Option<&dyn Registrar> {
        self.0.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        self.0.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        self.0.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<W>> {
        self.0.owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
        self.0.scopes()
    }

    fn response(&mut self, request: &mut W, kind: Template) -> Result<W::Response, Self::Error> {
        self.0.response(request, kind).map_err(Into::into)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        self.0.error(err).into()
    }

    fn web_error(&mut self, err: W::Error) -> Self::Error {
        self.0.web_error(err).into()
    }

    fn extension(&mut self) -> Option<&mut dyn Extension> {
        self.0.extension()
    }
}