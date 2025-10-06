use rumqttc::v5::mqttbytes::{v5::LastWill, QoS};
use rumqttc::v5::{Client, ConnectionError, MqttOptions};
use std::thread;
use std::time::Duration;

fn main() {
    pretty_env_logger::init();

    let mut mqttoptions = MqttOptions::new("test-1", "localhost", 1884);
    let will = LastWill::new("hello/world", "good bye", QoS::AtMostOnce, false, None);
    mqttoptions
        .set_keep_alive(Duration::from_secs(5))
        .set_last_will(will);

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

    let (client, mut eventloop) = MqttMtdClient::<HmacSha256, EphemeralX25519, Aes128Gcm, _>::new(
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

fn publish(client: Client) {
    client.subscribe("hello/+/world", QoS::AtMostOnce).unwrap();
    for i in 0..10_usize {
        let payload = vec![1; i];
        let topic = format!("hello/{i}/world");
        let qos = QoS::AtLeastOnce;

        let _ = client.publish(topic, qos, true, payload);
    }

    thread::sleep(Duration::from_secs(1));
}
