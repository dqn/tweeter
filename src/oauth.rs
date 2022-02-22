use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

// https://developer.twitter.com/ja/docs/basics/authentication/guides/authorizing-a-request
// https://developer.twitter.com/ja/docs/basics/authentication/guides/creating-a-signature

pub enum HttpMethod {
    POST,
}

impl ToString for HttpMethod {
    fn to_string(&self) -> String {
        match self {
            HttpMethod::POST => "POST".to_string(),
        }
    }
}

#[derive(Deserialize)]
pub struct Config {
    consumer_key: String,
    consumer_secret: String,
    access_token: String,
    access_token_secret: String,
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

// https://developer.twitter.com/ja/docs/basics/authentication/guides/percent-encoding-parameters
const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, FRAGMENT).to_string()
}

fn create_signing_key(consumer_secret: &str, access_token_secret: &str) -> String {
    format!("{consumer_secret}&{access_token_secret}")
}

fn create_signature_base(method: &HttpMethod, endpoint: &str, query: &Vec<(&str, &str)>) -> String {
    let mut pairs = query
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<String>>();
    pairs.sort_by(|a, b| a.cmp(b));

    format!(
        "{}&{}&{}",
        method.to_string(),
        percent_encode(endpoint),
        percent_encode(&pairs.join("&"))
    )
}

fn calc_oauth_signature(signing_key: &str, signature_base: &str) -> String {
    let mut hmac = Hmac::new(Sha1::new(), signing_key.as_bytes());
    hmac.input(signature_base.as_bytes());
    percent_encode(&base64::encode(hmac.result().code()))
}

pub fn build_header_string(
    config: &Config,
    method: &HttpMethod,
    url: &str,
    query: &Vec<(&str, &str)>,
) -> String {
    let nonce = random_string(32);
    let timestamp = timestamp().to_string();
    let mut oauth_params = vec![
        ("oauth_consumer_key", config.consumer_key.as_str()),
        ("oauth_nonce", &nonce),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", &timestamp),
        ("oauth_token", &config.access_token),
        ("oauth_version", "1.0"),
    ];
    let signing_key = create_signing_key(&config.consumer_secret, &config.access_token_secret);
    let signature_base_string =
        create_signature_base(&method, &url, &[&oauth_params[..], &query[..]].concat());
    let signature = calc_oauth_signature(&signing_key, &signature_base_string);
    oauth_params.push(("oauth_signature", &signature));
    let value = oauth_params
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<String>>()
        .join(", ");

    format!("OAuth {value}")
}
