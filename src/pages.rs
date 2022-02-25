use oxide_auth::{primitives::registrar::RegisteredUrl, endpoint::Scope};
use sailfish::TemplateOnce;

#[derive(TemplateOnce)]
#[template(path = "deny.stpl")]
pub(crate) struct DenyPage {}

#[derive(TemplateOnce)]
#[template(path = "auth.stpl")]
pub(crate) struct AuthPage<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) redirect_uri: &'a RegisteredUrl,
    pub(crate) scope: &'a Scope,
    pub(crate) route: &'a str,
    pub(crate) state: String,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String
}
