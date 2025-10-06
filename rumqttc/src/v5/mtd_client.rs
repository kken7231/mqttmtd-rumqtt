use std::marker::PhantomData;
use std::time::Duration;

use crate::v5::client::{resolve_event, subscribe_has_valid_filters};
use crate::v5::eventloop::MqttMtdEventLoop;
use crate::v5::mqttbytes::{valid_topic, QoS};
use crate::v5::{
    ClientError, ConnectionError, Event, MqttOptions, RecvError, RecvTimeoutError, Request,
    TryRecvError,
};

use super::mqttbytes::v5::{
    Filter, PubAck, PubRec, Publish, PublishProperties, Subscribe, SubscribeProperties,
    Unsubscribe, UnsubscribeProperties,
};

use bytes::Bytes;
use flume::Sender;
use futures_util::FutureExt;
use libmqttmtd::crypto::aead::AeadHandler;
use libmqttmtd::crypto::ephemeral::KeyAgreementHandler;
use libmqttmtd::crypto::hmac::HmacHandler;
use libmqttmtd::crypto::signature::DigitalSignatureHandler;
use libmqttmtd::handshake::client::MqttMtdClientOptions;
use tokio::runtime::{self, Runtime};
use tokio::time::timeout;

/// An asynchronous client, communicates with MQTT `EventLoop`.
///
/// This is cloneable and can be used to asynchronously [`publish`](`AsyncClient::publish`),
/// [`subscribe`](`AsyncClient::subscribe`) through the `EventLoop`, which is to be polled parallelly.
///
/// **NOTE**: The `EventLoop` must be regularly polled in order to send, receive and process packets
/// from the broker, i.e. move ahead.
#[derive(Clone, Debug)]
pub struct MqttMtdAsyncClient<
    H: HmacHandler,
    E: KeyAgreementHandler,
    A: AeadHandler,
    D: DigitalSignatureHandler,
> {
    request_tx: Sender<Request>,
    _p_h: PhantomData<H>,
    _p_e: PhantomData<E>,
    _p_a: PhantomData<A>,
    _p_d: PhantomData<D>,
}

impl<H: HmacHandler, E: KeyAgreementHandler, A: AeadHandler, D: DigitalSignatureHandler>
    MqttMtdAsyncClient<H, E, A, D>
{
    /// Create a new `AsyncClient`.
    ///
    /// `cap` specifies the capacity of the bounded async channel.
    pub fn new<'a>(
        options: MqttOptions,
        mtd_options: MqttMtdClientOptions<'a, H, E, A, D>,
        cap: usize,
    ) -> (
        MqttMtdAsyncClient<H, E, A, D>,
        MqttMtdEventLoop<'a, H, E, A, D>,
    ) {
        let eventloop = MqttMtdEventLoop::new(options, mtd_options, cap);
        let request_tx = eventloop.requests_tx.clone();

        let client: MqttMtdAsyncClient<H, E, A, D> = MqttMtdAsyncClient {
            request_tx,
            _p_h: PhantomData,
            _p_e: PhantomData,
            _p_a: PhantomData,
            _p_d: PhantomData,
        };

        (client, eventloop)
    }

    /// Create a new `AsyncClient` from a channel `Sender`.
    ///
    /// This is mostly useful for creating a test instance where you can
    /// listen on the corresponding receiver.
    pub fn from_senders(request_tx: Sender<Request>) -> MqttMtdAsyncClient<H, E, A, D> {
        MqttMtdAsyncClient {
            request_tx,
            _p_h: PhantomData,
            _p_e: PhantomData,
            _p_a: PhantomData,
            _p_d: PhantomData,
        }
    }

    /// Sends a MQTT Publish to the `EventLoop`.
    async fn handle_publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: Option<PublishProperties>,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        let topic = topic.into();
        let mut publish = Publish::new(&topic, qos, payload, properties);
        publish.retain = retain;
        let publish = Request::Publish(publish);
        if !valid_topic(&topic) {
            return Err(ClientError::Request(publish));
        }
        self.request_tx.send_async(publish).await?;
        Ok(())
    }

    pub async fn publish_with_properties<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: PublishProperties,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_publish(topic, qos, retain, payload, Some(properties))
            .await
    }

    pub async fn publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_publish(topic, qos, retain, payload, None).await
    }

    /// Attempts to send a MQTT Publish to the `EventLoop`.
    fn handle_try_publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: Option<PublishProperties>,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        let topic = topic.into();
        let mut publish = Publish::new(&topic, qos, payload, properties);
        publish.retain = retain;
        let publish = Request::Publish(publish);
        if !valid_topic(&topic) {
            return Err(ClientError::TryRequest(publish));
        }
        self.request_tx.try_send(publish)?;
        Ok(())
    }

    pub fn try_publish_with_properties<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: PublishProperties,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_try_publish(topic, qos, retain, payload, Some(properties))
    }

    pub fn try_publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_try_publish(topic, qos, retain, payload, None)
    }

    /// Sends a MQTT PubAck to the `EventLoop`. Only needed in if `manual_acks` flag is set.
    pub async fn ack(&self, publish: &Publish) -> Result<(), ClientError> {
        let ack = get_ack_req(publish);

        if let Some(ack) = ack {
            self.request_tx.send_async(ack).await?;
        }
        Ok(())
    }

    /// Attempts to send a MQTT PubAck to the `EventLoop`. Only needed in if `manual_acks` flag is set.
    pub fn try_ack(&self, publish: &Publish) -> Result<(), ClientError> {
        let ack = get_ack_req(publish);
        if let Some(ack) = ack {
            self.request_tx.try_send(ack)?;
        }
        Ok(())
    }

    /// Sends a MQTT Publish to the `EventLoop`
    async fn handle_publish_bytes<S>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: Bytes,
        properties: Option<PublishProperties>,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
    {
        let topic = topic.into();
        let mut publish = Publish::new(&topic, qos, payload, properties);
        publish.retain = retain;
        let publish = Request::Publish(publish);
        if !valid_topic(&topic) {
            return Err(ClientError::TryRequest(publish));
        }
        self.request_tx.send_async(publish).await?;
        Ok(())
    }

    pub async fn publish_bytes_with_properties<S>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: Bytes,
        properties: PublishProperties,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
    {
        self.handle_publish_bytes(topic, qos, retain, payload, Some(properties))
            .await
    }

    pub async fn publish_bytes<S>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: Bytes,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
    {
        self.handle_publish_bytes(topic, qos, retain, payload, None)
            .await
    }

    /// Sends a MQTT Subscribe to the `EventLoop`
    async fn handle_subscribe<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError> {
        let filter = Filter::new(topic, qos);
        let subscribe = Subscribe::new(filter, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::Request(subscribe.into()));
        }

        self.request_tx.send_async(subscribe.into()).await?;
        Ok(())
    }

    pub async fn subscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_subscribe(topic, qos, Some(properties)).await
    }

    pub async fn subscribe<S: Into<String>>(&self, topic: S, qos: QoS) -> Result<(), ClientError> {
        self.handle_subscribe(topic, qos, None).await
    }

    /// Attempts to send a MQTT Subscribe to the `EventLoop`
    fn handle_try_subscribe<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError> {
        let filter = Filter::new(topic, qos);
        let subscribe = Subscribe::new(filter, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::TryRequest(subscribe.into()));
        }

        self.request_tx.try_send(subscribe.into())?;
        Ok(())
    }

    pub fn try_subscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_try_subscribe(topic, qos, Some(properties))
    }

    pub fn try_subscribe<S: Into<String>>(&self, topic: S, qos: QoS) -> Result<(), ClientError> {
        self.handle_try_subscribe(topic, qos, None)
    }

    /// Sends a MQTT Subscribe for multiple topics to the `EventLoop`
    async fn handle_subscribe_many<T>(
        &self,
        topics: T,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        let subscribe = Subscribe::new_many(topics, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::Request(subscribe.into()));
        }

        self.request_tx.send_async(subscribe.into()).await?;

        Ok(())
    }

    pub async fn subscribe_many_with_properties<T>(
        &self,
        topics: T,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_subscribe_many(topics, Some(properties)).await
    }

    pub async fn subscribe_many<T>(&self, topics: T) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_subscribe_many(topics, None).await
    }

    /// Attempts to send a MQTT Subscribe for multiple topics to the `EventLoop`
    fn handle_try_subscribe_many<T>(
        &self,
        topics: T,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        let subscribe = Subscribe::new_many(topics, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::TryRequest(subscribe.into()));
        }

        self.request_tx.try_send(subscribe.into())?;
        Ok(())
    }

    pub fn try_subscribe_many_with_properties<T>(
        &self,
        topics: T,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_try_subscribe_many(topics, Some(properties))
    }

    pub fn try_subscribe_many<T>(&self, topics: T) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_try_subscribe_many(topics, None)
    }

    /// Sends a MQTT Unsubscribe to the `EventLoop`
    async fn handle_unsubscribe<S: Into<String>>(
        &self,
        topic: S,
        properties: Option<UnsubscribeProperties>,
    ) -> Result<(), ClientError> {
        let unsubscribe = Unsubscribe::new(topic, properties);
        let request = Request::Unsubscribe(unsubscribe);
        self.request_tx.send_async(request).await?;
        Ok(())
    }

    pub async fn unsubscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        properties: UnsubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_unsubscribe(topic, Some(properties)).await
    }

    pub async fn unsubscribe<S: Into<String>>(&self, topic: S) -> Result<(), ClientError> {
        self.handle_unsubscribe(topic, None).await
    }

    /// Attempts to send a MQTT Unsubscribe to the `EventLoop`
    fn handle_try_unsubscribe<S: Into<String>>(
        &self,
        topic: S,
        properties: Option<UnsubscribeProperties>,
    ) -> Result<(), ClientError> {
        let unsubscribe = Unsubscribe::new(topic, properties);
        let request = Request::Unsubscribe(unsubscribe);
        self.request_tx.try_send(request)?;
        Ok(())
    }

    pub fn try_unsubscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        properties: UnsubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_try_unsubscribe(topic, Some(properties))
    }

    pub fn try_unsubscribe<S: Into<String>>(&self, topic: S) -> Result<(), ClientError> {
        self.handle_try_unsubscribe(topic, None)
    }

    /// Sends a MQTT disconnect to the `EventLoop`
    pub async fn disconnect(&self) -> Result<(), ClientError> {
        let request = Request::Disconnect;
        self.request_tx.send_async(request).await?;
        Ok(())
    }

    /// Attempts to send a MQTT disconnect to the `EventLoop`
    pub fn try_disconnect(&self) -> Result<(), ClientError> {
        let request = Request::Disconnect;
        self.request_tx.try_send(request)?;
        Ok(())
    }
}

fn get_ack_req(publish: &Publish) -> Option<Request> {
    let ack = match publish.qos {
        QoS::AtMostOnce => return None,
        QoS::AtLeastOnce => Request::PubAck(PubAck::new(publish.pkid, None)),
        QoS::ExactlyOnce => Request::PubRec(PubRec::new(publish.pkid, None)),
    };
    Some(ack)
}

/// A synchronous client, communicates with MQTT `EventLoop`.
///
/// This is cloneable and can be used to synchronously [`publish`](`AsyncClient::publish`),
/// [`subscribe`](`AsyncClient::subscribe`) through the `EventLoop`/`Connection`, which is to be polled in parallel
/// by iterating over the object returned by [`Connection.iter()`](Connection::iter) in a separate thread.
///
/// **NOTE**: The `EventLoop`/`Connection` must be regularly polled(`.next()` in case of `Connection`) in order
/// to send, receive and process packets from the broker, i.e. move ahead.
///
/// An asynchronous channel handle can also be extracted if necessary.
#[derive(Clone)]
pub struct MqttMtdClient<
    H: HmacHandler,
    E: KeyAgreementHandler,
    A: AeadHandler,
    D: DigitalSignatureHandler,
> {
    client: MqttMtdAsyncClient<H, E, A, D>,
}

impl<H: HmacHandler, E: KeyAgreementHandler, A: AeadHandler, D: DigitalSignatureHandler>
    MqttMtdClient<H, E, A, D>
{
    /// Create a new `Client`
    ///
    /// `cap` specifies the capacity of the bounded async channel.
    pub fn new<'a>(
        options: MqttOptions,
        mtd_options: MqttMtdClientOptions<'a, H, E, A, D>,
        cap: usize,
    ) -> (MqttMtdClient<H, E, A, D>, MqttMtdConnection<'a, H, E, A, D>) {
        let (client, eventloop) = MqttMtdAsyncClient::new(options, mtd_options, cap);
        let client = MqttMtdClient { client };
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let connection = MqttMtdConnection::new(eventloop, runtime);
        (client, connection)
    }

    /// Create a new `Client` from a channel `Sender`.
    ///
    /// This is mostly useful for creating a test instance where you can
    /// listen on the corresponding receiver.
    pub fn from_sender(request_tx: Sender<Request>) -> MqttMtdClient<H, E, A, D> {
        MqttMtdClient {
            client: MqttMtdAsyncClient::<H, E, A, D>::from_senders(request_tx),
        }
    }

    /// Sends a MQTT Publish to the `EventLoop`
    fn handle_publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: Option<PublishProperties>,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        let topic = topic.into();
        let mut publish = Publish::new(&topic, qos, payload, properties);
        publish.retain = retain;
        let publish = Request::Publish(publish);
        if !valid_topic(&topic) {
            return Err(ClientError::Request(publish));
        }
        self.client.request_tx.send(publish)?;
        Ok(())
    }

    pub fn publish_with_properties<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: PublishProperties,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_publish(topic, qos, retain, payload, Some(properties))
    }

    pub fn publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.handle_publish(topic, qos, retain, payload, None)
    }

    pub fn try_publish_with_properties<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
        properties: PublishProperties,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.client
            .try_publish_with_properties(topic, qos, retain, payload, properties)
    }

    pub fn try_publish<S, P>(
        &self,
        topic: S,
        qos: QoS,
        retain: bool,
        payload: P,
    ) -> Result<(), ClientError>
    where
        S: Into<String>,
        P: Into<Bytes>,
    {
        self.client.try_publish(topic, qos, retain, payload)
    }

    /// Sends a MQTT PubAck to the `EventLoop`. Only needed in if `manual_acks` flag is set.
    pub fn ack(&self, publish: &Publish) -> Result<(), ClientError> {
        let ack = get_ack_req(publish);

        if let Some(ack) = ack {
            self.client.request_tx.send(ack)?;
        }
        Ok(())
    }

    /// Sends a MQTT PubAck to the `EventLoop`. Only needed in if `manual_acks` flag is set.
    pub fn try_ack(&self, publish: &Publish) -> Result<(), ClientError> {
        self.client.try_ack(publish)?;
        Ok(())
    }

    /// Sends a MQTT Subscribe to the `EventLoop`
    fn handle_subscribe<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError> {
        let filter = Filter::new(topic, qos);
        let subscribe = Subscribe::new(filter, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::Request(subscribe.into()));
        }

        self.client.request_tx.send(subscribe.into())?;
        Ok(())
    }

    pub fn subscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_subscribe(topic, qos, Some(properties))
    }

    pub fn subscribe<S: Into<String>>(&self, topic: S, qos: QoS) -> Result<(), ClientError> {
        self.handle_subscribe(topic, qos, None)
    }

    /// Sends a MQTT Subscribe to the `EventLoop`
    pub fn try_subscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        qos: QoS,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError> {
        self.client
            .try_subscribe_with_properties(topic, qos, properties)
    }

    pub fn try_subscribe<S: Into<String>>(&self, topic: S, qos: QoS) -> Result<(), ClientError> {
        self.client.try_subscribe(topic, qos)
    }

    /// Sends a MQTT Subscribe for multiple topics to the `EventLoop`
    fn handle_subscribe_many<T>(
        &self,
        topics: T,
        properties: Option<SubscribeProperties>,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        let subscribe = Subscribe::new_many(topics, properties);
        if !subscribe_has_valid_filters(&subscribe) {
            return Err(ClientError::Request(subscribe.into()));
        }

        self.client.request_tx.send(subscribe.into())?;
        Ok(())
    }

    pub fn subscribe_many_with_properties<T>(
        &self,
        topics: T,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_subscribe_many(topics, Some(properties))
    }

    pub fn subscribe_many<T>(&self, topics: T) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.handle_subscribe_many(topics, None)
    }

    pub fn try_subscribe_many_with_properties<T>(
        &self,
        topics: T,
        properties: SubscribeProperties,
    ) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.client
            .try_subscribe_many_with_properties(topics, properties)
    }

    pub fn try_subscribe_many<T>(&self, topics: T) -> Result<(), ClientError>
    where
        T: IntoIterator<Item = Filter>,
    {
        self.client.try_subscribe_many(topics)
    }

    /// Sends a MQTT Unsubscribe to the `EventLoop`
    fn handle_unsubscribe<S: Into<String>>(
        &self,
        topic: S,
        properties: Option<UnsubscribeProperties>,
    ) -> Result<(), ClientError> {
        let unsubscribe = Unsubscribe::new(topic, properties);
        let request = Request::Unsubscribe(unsubscribe);
        self.client.request_tx.send(request)?;
        Ok(())
    }

    pub fn unsubscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        properties: UnsubscribeProperties,
    ) -> Result<(), ClientError> {
        self.handle_unsubscribe(topic, Some(properties))
    }

    pub fn unsubscribe<S: Into<String>>(&self, topic: S) -> Result<(), ClientError> {
        self.handle_unsubscribe(topic, None)
    }

    /// Sends a MQTT Unsubscribe to the `EventLoop`
    pub fn try_unsubscribe_with_properties<S: Into<String>>(
        &self,
        topic: S,
        properties: UnsubscribeProperties,
    ) -> Result<(), ClientError> {
        self.client
            .try_unsubscribe_with_properties(topic, properties)
    }

    pub fn try_unsubscribe<S: Into<String>>(&self, topic: S) -> Result<(), ClientError> {
        self.client.try_unsubscribe(topic)
    }

    /// Sends a MQTT disconnect to the `EventLoop`
    pub fn disconnect(&self) -> Result<(), ClientError> {
        let request = Request::Disconnect;
        self.client.request_tx.send(request)?;
        Ok(())
    }

    /// Sends a MQTT disconnect to the `EventLoop`
    pub fn try_disconnect(&self) -> Result<(), ClientError> {
        self.client.try_disconnect()?;
        Ok(())
    }
}
pub struct MqttMtdConnection<
    'a,
    H: HmacHandler,
    E: KeyAgreementHandler,
    A: AeadHandler,
    D: DigitalSignatureHandler,
> {
    pub eventloop: MqttMtdEventLoop<'a, H, E, A, D>,
    runtime: Runtime,
}
impl<'a, H: HmacHandler, E: KeyAgreementHandler, A: AeadHandler, D: DigitalSignatureHandler>
    MqttMtdConnection<'a, H, E, A, D>
{
    fn new(
        eventloop: MqttMtdEventLoop<'a, H, E, A, D>,
        runtime: Runtime,
    ) -> MqttMtdConnection<'a, H, E, A, D> {
        MqttMtdConnection { eventloop, runtime }
    }

    /// Returns an iterator over this connection. Iterating over this is all that's
    /// necessary to make connection progress and maintain a robust connection.
    /// Just continuing to loop will reconnect
    /// **NOTE** Don't block this while iterating
    // ideally this should be named iter_mut because it requires a mutable reference
    // Also we can implement IntoIter for this to make it easy to iterate over it
    #[must_use = "Connection should be iterated over a loop to make progress"]
    pub fn iter(&mut self) -> MqttMtdIter<'a, '_, H, E, A, D> {
        MqttMtdIter { connection: self }
    }

    /// Attempt to fetch an incoming [`Event`] on the [`EventLoop`], returning an error
    /// if all clients/users have closed requests channel.
    ///
    /// [`EventLoop`]: super::EventLoop
    pub fn recv(&mut self) -> Result<Result<Event, ConnectionError>, RecvError> {
        let f = self.eventloop.poll();
        let event = self.runtime.block_on(f);

        resolve_event(event).ok_or(RecvError)
    }

    /// Attempt to fetch an incoming [`Event`] on the [`EventLoop`], returning an error
    /// if none immediately present or all clients/users have closed requests channel.
    ///
    /// [`EventLoop`]: super::EventLoop
    pub fn try_recv(&mut self) -> Result<Result<Event, ConnectionError>, TryRecvError> {
        let f = self.eventloop.poll();
        // Enters the runtime context so we can poll the future, as required by `now_or_never()`.
        // ref: https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html#method.enter
        let _guard = self.runtime.enter();
        let event = f.now_or_never().ok_or(TryRecvError::Empty)?;

        resolve_event(event).ok_or(TryRecvError::Disconnected)
    }

    /// Attempt to fetch an incoming [`Event`] on the [`EventLoop`], returning an error
    /// if all clients/users have closed requests channel or the timeout has expired.
    ///
    /// [`EventLoop`]: super::EventLoop
    pub fn recv_timeout(
        &mut self,
        duration: Duration,
    ) -> Result<Result<Event, ConnectionError>, RecvTimeoutError> {
        let f = self.eventloop.poll();
        let event = self
            .runtime
            .block_on(async { timeout(duration, f).await })
            .map_err(|_| RecvTimeoutError::Timeout)?;

        resolve_event(event).ok_or(RecvTimeoutError::Disconnected)
    }
}

/// Iterator which polls the `EventLoop` for connection progress
pub struct MqttMtdIter<
    'a,
    'b,
    H: HmacHandler,
    E: KeyAgreementHandler,
    A: AeadHandler,
    D: DigitalSignatureHandler,
> {
    connection: &'a mut MqttMtdConnection<'b, H, E, A, D>,
}

impl<H: HmacHandler, E: KeyAgreementHandler, A: AeadHandler, D: DigitalSignatureHandler> Iterator
    for MqttMtdIter<'_, '_, H, E, A, D>
{
    type Item = Result<Event, ConnectionError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.connection.recv().ok()
    }
}
