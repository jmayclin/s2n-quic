// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_quic::{
    provider::{tls::default::{
        certificate::{self, IntoCertificate, IntoPrivateKey},
        rustls,
    }, limits::{Limiter, ConnectionInfo, Limits}},
    Server,
};
use s2n_quic_rustls::server::SometimesResolvesChain;
use std::{error::Error, sync::Arc};

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!(concat!(
    "../../../../quic/s2n-quic-core/certs/cert.pem"
));
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!(concat!(
    "../../../../quic/s2n-quic-core/certs/key.pem"
));

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static FANCY_CERT_PEM: &str = include_str!(concat!(
    "../../cert.pem"
));
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static FANCY_KEY_PEM: &str = include_str!(concat!(
    "../../key.pem"
));


// this is for demo purposes only, so don't @ me


/**
       let server = Server::builder()
           .with_io(io)?
           .with_endpoint_limits(limits)?
           .with_event((
               EventSubscriber(1),
               s2n_quic::provider::event::tracing::Subscriber::default(),
           ))?;
       let server = match self.tls {
           TlsProviders::S2N => {
               // The server builder defaults to a chain because this allows certs to just work, whether
               // the PEM contains a single cert or a chain
               let tls = self.build_s2n_tls_server()?;

               server.with_tls(tls)?.start().unwrap()
           }
           TlsProviders::Rustls => {
               // The server builder defaults to a chain because this allows certs to just work, whether
               // the PEM contains a single cert or a chain
               let tls = s2n_quic::provider::tls::rustls::Server::builder()
                   .with_certificate(
                       tls::rustls::ca(self.certificate.as_ref())?,
                       tls::rustls::private_key(self.private_key.as_ref())?,
                   )?
                   .with_application_protocols(
                       self.application_protocols.iter().map(String::as_bytes),
                   )?
                   .with_key_logging()?
                   .build()?;

               server.with_tls(tls)?.start().unwrap()
           }
       };
*/

// my connection impl thing
#[derive(Clone)]
struct MySpecialLimits;

/// Implement Limiter for a Limits struct
impl Limiter for MySpecialLimits {
    fn on_connection(&mut self, into: &ConnectionInfo) -> Limits {
        let limits = Limits::new();
        let sni = std::str::from_utf8(&into.server_name.as_ref().unwrap()).unwrap();
        //println!("I'm the connection limits provider");
        println!("[Setting connection limits] : sni was {}", sni);
        if sni == "gimme.moar.bandwidth" {
            println!("[Setting connection limits] : You wanted more bandwidth. Returning a data window of 999_999_999. That seems ill-considered, but exciting!");
            limits.with_data_window(999_999_999).unwrap()
        } else {
            println!("[Setting connection limits] : You're just some nobody. Boring");
            limits
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let special_limiter = MySpecialLimits;
    let sometimes_resolver = SometimesResolvesChain::new(
        CERT_PEM.into_certificate().unwrap(),
        KEY_PEM.into_private_key().unwrap(),
        FANCY_CERT_PEM.into_certificate().unwrap(),
        FANCY_KEY_PEM.into_private_key().unwrap(),
    ).unwrap();
    let sometimes_resolver = Arc::new(sometimes_resolver);
    let rustls = s2n_quic::provider::tls::rustls::Server::builder().with_cert_resolver(sometimes_resolver)?.build()?;
    let mut server = Server::builder()
        .with_tls(rustls)?
        .with_io("127.0.0.1:4433")?
        .with_limits(special_limiter)?
        .start()?;

    while let Some(mut connection) = server.accept().await {
        // spawn a new task for the connection
        tokio::spawn(async move {
            eprintln!("Connection accepted from {:?}", connection.remote_addr());

            while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
                // spawn a new task for the stream
                tokio::spawn(async move {
                    eprintln!("Stream opened from {:?}", stream.connection().remote_addr());

                    // echo any data back to the stream
                    while let Ok(Some(data)) = stream.receive().await {
                        stream.send(data).await.expect("stream should be open");
                    }
                });
            }
        });
    }

    Ok(())
}
