use libmqttmtd::crypto::signature::DigitalSignatureSigner;
use libmqttmtd::crypto_ring::aead::Aes128Gcm;
use libmqttmtd::crypto_ring::ephemeral::EphemeralX25519;
use libmqttmtd::crypto_ring::hmac::HmacSha256;
use libmqttmtd::crypto_ring::signature::RsaPssSha256;
use libmqttmtd::handshake::client::MqttMtdClientOptions;
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
        StaticTopicString::from("topic/pn1"),
        StaticTopicString::from("topic/pn2"),
    ]);
    let topic_filters = StaticTopicStringSet::from([
        StaticTopicString::from("topic/sf1"),
        StaticTopicString::from("topic/sf2"),
    ]);
    let auth_req = Arc::new(StaticAuthRequest::new(topic_names, topic_filters)?);

    // Dummies to prevent compilation error in CI
    let ca = "abc";
    let server_cert = "abc";
    let client_cert = "abc";
    let client_key = "abc";
    //     let ca = include_str!("/home/tekjar/tlsfiles/ca.cert.pem");
    //     let server_cert = include_str!("/home/tekjar/tlsfiles/server.cert.pem");
    //     let client_cert = include_str!("/home/tekjar/tlsfiles/device-1.cert.pem");
    //     let client_key = include_str!("/home/tekjar/tlsfiles/device-1.key.pem");

    let server_cv_verifier = DigitalSignatureVerifier::<RsaPssSha256<4096>>::from_pkcs8_pem(
        server_cert,
        &webpki::TlsClientTrustAnchors(&[]),
    )?;
    let client_cv_signer = DigitalSignatureSigner::<RsaPssSha256<4096>>::from_pkcs8_pem(client_key);
    let cert_chain = CertificateChain::from_pkcs8_pem(&[client_cert.as_bytes()])?;
    let buffer_capacity = 2048;

    let mut mtdoptions = MqttMtdClientOptions::new(
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

async fn requests(client: MqttMtdAsyncClient) {
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
