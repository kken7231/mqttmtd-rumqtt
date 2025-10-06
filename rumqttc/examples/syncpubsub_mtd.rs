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

use rumqttc::{ConnectionError, LastWill, MqttMtdClient, MqttOptions, QoS};
use std::thread;
use std::time::Duration;

fn main() {
    pretty_env_logger::init();

    let mut mqttoptions = MqttOptions::new("test-1", "localhost", 1884);
    let will = LastWill::new("hello/world", "good bye", QoS::AtMostOnce, false);
    mqttoptions
        .set_keep_alive(Duration::from_secs(5))
        .set_last_will(will);

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

    let (client, mut connection) = MqttMtdClient::<HmacSha256, EphemeralX25519, Aes128Gcm, _>::new(
        mqttoptions,
        mtdoptions,
        10,
    );
    thread::spawn(move || publish(client));

    for (i, notification) in connection.iter().enumerate() {
        match notification {
            Err(ConnectionError::Io(error))
                if error.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                println!("Failed to connect to the server. Make sure correct client is configured properly!\nError: {error:?}");
                return;
            }
            _ => {}
        }
        println!("{i}. Notification = {notification:?}");
    }

    println!("Done with the stream!!");
}

fn publish<H: HmacHandler, E: KeyAgreementHandler, A: AeadHandler, D: DigitalSignatureHandler>(
    client: MqttMtdClient<H, E, A, D>,
) {
    client.subscribe("hello/world", QoS::AtMostOnce).unwrap();
    for i in 0..10_usize {
        let payload = vec![1; i];
        let topic = format!("hello/world");
        let qos = QoS::AtMostOnce;

        let _ = client.publish(topic, qos, true, payload);
        thread::sleep(Duration::from_secs(1));
    }

    thread::sleep(Duration::from_secs(1));
}
