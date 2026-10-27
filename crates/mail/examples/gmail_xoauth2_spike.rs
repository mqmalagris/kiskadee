//! Phase 0 spike: Gmail over XOAUTH2 with a bring-your-own Google client ID.
//!
//! Env:
//!   KISKADEE_GOOGLE_CLIENT_JSON  path to the "Desktop app" client JSON
//!   KISKADEE_GMAIL_USER          the Gmail address to sign in as
//! Modes (first arg):
//!   login    (default) OAuth loopback + PKCE if no stored refresh token, then IMAP + SMTP checks
//!   refresh  use only the stored refresh token (re-run after 7 days to test expiry)
//!   forget   revoke the refresh token at Google and delete it from the keychain
//! Tokens are never printed. Throwaway code: the real flow lands in Phase 2.

use std::io::{Read, Write};
use std::net::TcpListener;

use async_imap::Authenticator;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RefreshToken, RevocationUrl, Scope, StandardRevocableToken, TokenResponse, TokenUrl, reqwest,
};

type Error = Box<dyn std::error::Error>;

const KEYCHAIN_KEY: &str = "spike-gmail-refresh-token";
const SCOPE: &str = "https://mail.google.com/";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "login".into());
    let user = env("KISKADEE_GMAIL_USER")?;
    let (client_id, client_secret) = read_client_json(&env("KISKADEE_GOOGLE_CLIENT_JSON")?)?;
    kiskadee_platform::keychain::init()?;

    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let redirect = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let oauth = BasicClient::new(ClientId::new(client_id))
        .set_client_secret(ClientSecret::new(client_secret))
        .set_auth_uri(AuthUrl::new(
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
        )?)
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".into())?)
        .set_revocation_url(RevocationUrl::new(
            "https://oauth2.googleapis.com/revoke".into(),
        )?)
        .set_redirect_uri(RedirectUrl::new(redirect)?);

    let stored = kiskadee_platform::keychain::get(KEYCHAIN_KEY)?
        .map(String::from_utf8)
        .transpose()?;

    if mode == "forget" {
        if let Some(token) = stored {
            oauth
                .revoke_token(StandardRevocableToken::RefreshToken(RefreshToken::new(
                    token,
                )))?
                .request_async(&http)
                .await?;
            println!("revoked at Google");
        }
        kiskadee_platform::keychain::delete(KEYCHAIN_KEY)?;
        println!("deleted from keychain");
        return Ok(());
    }

    let refresh_token = match (stored, mode.as_str()) {
        (Some(token), _) => {
            println!("1. using stored refresh token from the OS keychain");
            token
        }
        (None, "refresh") => return Err("no stored refresh token; run `login` first".into()),
        (None, _) => {
            println!("1. no stored token: starting the browser consent flow");
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            let (url, csrf) = oauth
                .authorize_url(CsrfToken::new_random)
                .add_scope(Scope::new(SCOPE.into()))
                .add_extra_param("access_type", "offline")
                .add_extra_param("prompt", "consent")
                .add_extra_param("login_hint", &user)
                .set_pkce_challenge(challenge)
                .url();
            if webbrowser::open(url.as_str()).is_err() {
                println!("   open this URL:\n{url}");
            }
            let (code, state) = wait_for_redirect(&listener)?;
            if state != *csrf.secret() {
                return Err("OAuth state mismatch (possible CSRF)".into());
            }
            let tokens = oauth
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(verifier)
                .request_async(&http)
                .await?;
            let token = tokens
                .refresh_token()
                .ok_or("Google returned no refresh token")?
                .secret()
                .clone();
            kiskadee_platform::keychain::put(KEYCHAIN_KEY, token.as_bytes())?;
            println!("   stored refresh token in the OS keychain");
            token
        }
    };

    println!("2. refreshing an access token");
    let access = oauth
        .exchange_refresh_token(&RefreshToken::new(refresh_token))
        .request_async(&http)
        .await?;
    let access = access.access_token().secret().clone();
    println!("   ok (access token not shown)");

    println!("3. IMAP XOAUTH2 login to imap.gmail.com:993");
    let tcp = tokio::net::TcpStream::connect(("imap.gmail.com", 993)).await?;
    let tls = async_native_tls::TlsConnector::new()
        .connect("imap.gmail.com", tcp)
        .await?;
    let mut client = async_imap::Client::new(tls);
    client.read_response().await?;
    let mut session = client
        .authenticate(
            "XOAUTH2",
            XOAuth2 {
                user: &user,
                token: &access,
            },
        )
        .await
        .map_err(|(error, _)| error)?;
    let capabilities = session.capabilities().await?;
    println!(
        "   CONDSTORE = {}, QRESYNC = {}",
        capabilities.has_str("CONDSTORE"),
        capabilities.has_str("QRESYNC")
    );
    let inbox = session.select("INBOX").await?;
    println!(
        "   INBOX: {} messages, uidvalidity {:?}, highestmodseq {:?}",
        inbox.exists, inbox.uid_validity, inbox.highest_modseq
    );
    session.logout().await?;

    println!("4. SMTP XOAUTH2 auth check on smtp.gmail.com:587 (sends nothing)");
    use lettre::transport::smtp::authentication::{Credentials, Mechanism};
    let smtp: lettre::AsyncSmtpTransport<lettre::Tokio1Executor> =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay("smtp.gmail.com")?
            .credentials(Credentials::new(user.clone(), access.clone()))
            .authentication(vec![Mechanism::Xoauth2])
            .build();
    println!("   authenticated = {}", smtp.test_connection().await?);

    println!("SPIKE PASSED");
    Ok(())
}

struct XOAuth2<'a> {
    user: &'a str,
    token: &'a str,
}

impl Authenticator for XOAuth2<'_> {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

/// Accepts the single OAuth redirect on the loopback listener.
fn wait_for_redirect(listener: &TcpListener) -> Result<(String, String), Error> {
    let (mut stream, _) = listener.accept()?;
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let path = request.split_whitespace().nth(1).ok_or("bad redirect")?;
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let param = |key: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .map(|value| value.replace("%2F", "/").replace("%2f", "/"))
    };
    let body = "kiskadee: you can close this tab and go back to the terminal.";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )?;
    if let Some(error) = param("error") {
        return Err(format!("consent refused: {error}").into());
    }
    Ok((
        param("code").ok_or("no code in redirect")?,
        param("state").ok_or("no state in redirect")?,
    ))
}

fn read_client_json(path: &str) -> Result<(String, String), Error> {
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let installed = &json["installed"];
    let field = |name: &str| {
        installed[name].as_str().map(str::to_string).ok_or_else(|| {
            format!("client JSON has no installed.{name}; is it a Desktop app client?")
        })
    };
    Ok((field("client_id")?, field("client_secret")?))
}

fn env(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| format!("{key} not set").into())
}
