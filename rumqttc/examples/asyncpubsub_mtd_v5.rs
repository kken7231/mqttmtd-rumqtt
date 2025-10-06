use libmqttmtd::authreq::{StaticAuthRequest, StaticTopicString, StaticTopicStringSet};
use libmqttmtd::crypto::aead::AeadHandler;
use libmqttmtd::crypto::ephemeral::KeyAgreementHandler;
use libmqttmtd::crypto::hmac::HmacHandler;
use libmqttmtd::crypto::signature::{
    DigitalSignatureHandler, DigitalSignatureSigner, DigitalSignatureVerifier,
    TlsClientTrustAnchors,
};
use libmqttmtd::crypto_rust_crypto::aead::Aes128Gcm;
use libmqttmtd::crypto_rust_crypto::ephemeral::EphemeralX25519;
use libmqttmtd::crypto_rust_crypto::hmac::HmacSha256;
use libmqttmtd::crypto_rust_crypto::signature::RsaPssSha256;
use libmqttmtd::handshake::client::MqttMtdClientOptions;
use libmqttmtd::handshake::CertificateChain;
use rumqttc::v5::mqttbytes::QoS;
use tokio::{task, time};

use rumqttc::v5::{MqttMtdAsyncClient, MqttOptions};
use std::error::Error;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    // color_backtrace::install();

    let mut mqttoptions = MqttOptions::new("test-1", "localhost", 1886);
    mqttoptions.set_keep_alive(Duration::from_secs(5));

    let topic_names = StaticTopicStringSet::from([
        StaticTopicString::from("hello/world"),
        StaticTopicString::from("hello/world/1"),
    ]);
    let topic_filters = StaticTopicStringSet::from([
        StaticTopicString::from("hello/world"),
        StaticTopicString::from("hello/world/1"),
    ]);
    let auth_req = StaticAuthRequest::new(topic_names, topic_filters).unwrap();

    // Dummies to prevent compilation error in CI
    // let server_cert = "abc";
    // let client_cert = "abc";
    // let client_key = "abc";
    let server_cert =
        include_str!("/Users/kentarou/git/mqttmtd-gateway-rs/certs/server/server.crt");
    let client_cert =
        include_str!("/Users/kentarou/git/mqttmtd-gateway-rs/certs/clients/client1.crt");
    let client_key =
        include_str!("/Users/kentarou/git/mqttmtd-gateway-rs/certs/clients/client1.pem");

    let server_cv_verifier = DigitalSignatureVerifier::<RsaPssSha256<2048>>::from_pkcs8_pem(
        server_cert,
        &TlsClientTrustAnchors(&[]),
    )
    .unwrap();
    let client_cv_signer =
        DigitalSignatureSigner::<RsaPssSha256<2048>>::from_pkcs8_pem(client_key).unwrap();
    let cert_chain = CertificateChain::from_pkcs8_pem(&[client_cert.as_bytes()]).unwrap();
    let buffer_capacity = 2048;

    let mtdoptions = MqttMtdClientOptions::new(
        server_cv_verifier,
        client_cv_signer,
        auth_req,
        cert_chain,
        buffer_capacity,
    );

    let (client, mut eventloop) =
        MqttMtdAsyncClient::<HmacSha256, EphemeralX25519, Aes128Gcm, _>::new(
            mqttoptions,
            mtdoptions,
            10,
        );
    task::spawn(async move {
        requests(client).await;
        time::sleep(Duration::from_secs(3)).await;
    });

    loop {
        let event = eventloop.poll().await;
        match &event {
            Ok(v) => {
                println!("Event = {v:?}");
            }
            Err(e) => {
                println!("Error = {e:?}");
                return Ok(());
            }
        }
    }
}

async fn requests<
    H: HmacHandler,
    E: KeyAgreementHandler,
    A: AeadHandler,
    D: DigitalSignatureHandler,
>(
    client: MqttMtdAsyncClient<H, E, A, D>,
) {
    client
        .subscribe("hello/world", QoS::AtMostOnce)
        .await
        .unwrap();

    for i in 1..=10 {
        client
            .publish("hello/world", QoS::ExactlyOnce, false, vec![1; i])
            .await
            .unwrap();

        time::sleep(Duration::from_secs(1)).await;
    }

    time::sleep(Duration::from_secs(120)).await;
}
