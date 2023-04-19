// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use rustls_mtls::{initialize_logger, MtlsProvider, handshake_waiter::HandshakeWaiter};
use s2n_quic::{client::Connect, Client};
use std::{error::Error, net::SocketAddr};

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CACERT_PEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/ca-cert.pem");
// uncomment this one to see the failure mode
pub static MY_CERT_PEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/client-ss.pem");
//pub static MY_CERT_PEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/client-cert.pem");
pub static MY_KEY_PEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/client-key.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    initialize_logger("client");
    let provider = MtlsProvider::new(CACERT_PEM, MY_CERT_PEM, MY_KEY_PEM).await?;
    let (rx, waiter) = HandshakeWaiter::new();
    let client = Client::builder()
        .with_event(s2n_quic::provider::event::tracing::Subscriber::default())?
        .with_tls(provider)?
        .with_io("0.0.0.0:0")?
        .with_event((s2n_quic::provider::event::tracing::Subscriber::default(), waiter))?
        .start()?;

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;
    println!("just gonna do a little nap until the handshake gets confirmed");
    match rx.await {
        Ok(message) => {match message {
            Ok(_) => {println!("the server told me to tell you that they think your certificate is pretty")},
            Err(_) => {panic!("the server told me to tell you that they think your certificate is ugly and they hate it.")}
        }},
        Err(_) => panic!("something interior to the channel failed"),
    };

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.open_bidirectional_stream().await?;
    let (mut receive_stream, mut send_stream) = stream.split();

    // spawn a task that copies responses from the server to stdout
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut receive_stream, &mut stdout).await;
    });

    // copy data from stdin and send it to the server
    let mut stdin = tokio::io::stdin();
    tokio::io::copy(&mut stdin, &mut send_stream).await?;

    Ok(())
}
