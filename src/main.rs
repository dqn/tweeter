mod oauth;

use anyhow::Result;
use chrono::prelude::*;
use dotenv::dotenv;
use oauth::{build_header_string, Config, HttpMethod};
use std::thread::sleep;
use url::Url;

fn sleep_until(timestamp_millis: i64) {
    sleep(std::time::Duration::from_millis(
        (timestamp_millis - Local::now().timestamp_millis()) as u64,
    ));
}

#[tokio::main]
async fn main() -> Result<()> {
    let status = "2022/2/22 22:22:22";
    let tweet_datetime = Local.ymd(2022, 2, 22).and_hms_milli(22, 22, 22, 222);

    dotenv()?;
    let config = envy::from_env::<Config>()?;

    let url = "https://api.twitter.com/1.1/statuses/update.json";
    let params = &vec![("status", status)];

    let tweet_timestamp_millis = tweet_datetime.timestamp_millis();
    let prepare_before_millis = 300; // For oauth_timestamp, authorization header needs to be prepared just before tweeting
    sleep_until(tweet_timestamp_millis - prepare_before_millis);

    let authorization = build_header_string(&config, &HttpMethod::POST, url, params);

    let req = reqwest::Client::new()
        .post(Url::parse_with_params(url, params)?)
        .header("Authorization", &authorization)
        .json(params);

    let tweet_before_millis = 140; // correction millis
    sleep_until(tweet_timestamp_millis - tweet_before_millis);

    let res = req.send().await?;

    println!("{}", res.status());
    println!("{}", res.text().await?);

    Ok(())
}
