// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Noise protocol handshake I/O.

pub(super) mod proto {
    #![allow(unreachable_pub)]
    include!("../generated/mod.rs");
    pub use self::payload::proto::{NoiseExtensions, NoiseHandshakePayload};
}

use std::{collections::HashSet, io};

use asynchronous_codec::Framed;
use futures::prelude::*;
use libp2p_identity as identity;
use multihash::Multihash;
use quick_protobuf::MessageWrite;

use super::framed::{Codec, DecodedItem, StaticHandshakePayloadOrBytes};
use crate::{
    io::Output,
    protocol::{ClatterSession, KeypairIdentity, PublicKey, STATIC_KEY_DOMAIN},
    Error,
};

//////////////////////////////////////////////////////////////////////////////
// Internal

/// Handshake state.
pub(crate) struct State<T> {
    /// The underlying I/O resource.
    io: Framed<T, Codec>,
    /// The associated public identity of the local node's static DH keypair,
    /// which can be sent to the remote as part of an authenticated handshake.
    identity: KeypairIdentity,
    /// The received signature over the remote's static DH public key, if any.
    dh_remote_pubkey_sig: Option<Vec<u8>>,
    /// The known or received public identity key of the remote, if any.
    id_remote_pubkey: Option<identity::PublicKey>,
    /// The DH public key for signature verification (stored separately from handshake key)
    dh_remote_pubkey: Option<Vec<u8>>,
    /// The WebTransport certhashes of the responder, if any.
    responder_webtransport_certhashes: Option<HashSet<Multihash>>,
    /// The received extensions of the remote, if any.
    remote_extensions: Option<Extensions>,
}

/// Extensions
struct Extensions {
    webtransport_certhashes: HashSet<Multihash>,
}

impl<T> State<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// Initializes the state for a new Noise handshake, using the given local
    /// identity keypair and local DH static public key. The handshake messages
    /// will be sent and received on the given I/O resource and using the
    /// provided session for cryptographic operations according to the chosen
    /// Noise handshake pattern.
    pub(crate) fn new(
        io: T,
        session: ClatterSession,
        identity: KeypairIdentity,
        expected_remote_key: Option<identity::PublicKey>,
        responder_webtransport_certhashes: Option<HashSet<Multihash>>,
    ) -> Self {
        Self {
            identity,
            io: Framed::new(io, Codec::new_handshake(session)),
            dh_remote_pubkey_sig: None,
            id_remote_pubkey: expected_remote_key,
            responder_webtransport_certhashes,
            remote_extensions: None,
            dh_remote_pubkey: None,
        }
    }
}

impl<T> State<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// Finish a handshake, yielding the established remote identity and the
    /// [`Output`] for communicating on the encrypted channel.
    pub(crate) fn finish(self) -> Result<(identity::PublicKey, Output<T>), Error> {
        let is_initiator = self.io.codec().is_initiator();

        let (pubkey, framed) = map_into_transport(self.io)?;

        let id_pk = self
            .id_remote_pubkey
            .ok_or_else(|| Error::AuthenticationFailed)?;

        // For signature verification, use the DH public key if available (PQ case)
        // Otherwise use the handshake public key (classical case)
        let key_for_signature = self
            .dh_remote_pubkey
            .as_ref()
            .map(|k| k.as_slice())
            .unwrap_or_else(|| pubkey.as_ref());

        let is_valid_signature = self.dh_remote_pubkey_sig.as_ref().is_some_and(|s| {
            let message = [STATIC_KEY_DOMAIN.as_bytes(), key_for_signature].concat();
            id_pk.verify(&message, s)
        });
        if !is_valid_signature {
            return Err(Error::BadSignature);
        }

        // Check WebTransport certhashes that responder reported back to us.
        if is_initiator {
            // We check only if we care (i.e. Config::with_webtransport_certhashes was used).
            if let Some(expected_certhashes) = self.responder_webtransport_certhashes {
                let ext = self.remote_extensions.ok_or_else(|| {
                    Error::UnknownWebTransportCerthashes(
                        expected_certhashes.to_owned(),
                        HashSet::new(),
                    )
                })?;

                let received_certhashes = ext.webtransport_certhashes;

                // Expected WebTransport certhashes must be a strict subset
                // of the reported ones.
                if !expected_certhashes.is_subset(&received_certhashes) {
                    return Err(Error::UnknownWebTransportCerthashes(
                        expected_certhashes,
                        received_certhashes,
                    ));
                }
            }
        }

        Ok((id_pk, Output::new(framed)))
    }
}

/// Maps the provided [`Framed`] from the handshake state into the transport state.
///
/// This extracts the codec, transitions it to transport mode, and reconstructs the framed
/// with the transport codec while preserving any buffered data.
fn map_into_transport<T>(framed: Framed<T, Codec>) -> Result<(PublicKey, Framed<T, Codec>), Error>
where
    T: AsyncRead + AsyncWrite,
{
    let parts = framed.into_parts();
    let (pubkey, transport_codec) = parts.codec.into_transport()?;
    let framed = Framed::new(parts.io, transport_codec);

    Ok((pubkey, framed))
}

impl From<proto::NoiseExtensions> for Extensions {
    fn from(value: proto::NoiseExtensions) -> Self {
        Extensions {
            webtransport_certhashes: value
                .webtransport_certhashes
                .into_iter()
                .filter_map(|bytes| Multihash::read(&bytes[..]).ok())
                .collect(),
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// Handshake Message Futures

/// A future for receiving a Noise handshake message.
async fn recv<T>(state: &mut State<T>) -> Result<proto::NoiseHandshakePayload, Error>
where
    T: AsyncRead + Unpin,
{
    match state.io.next().await {
        None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof").into()),
        Some(Err(e)) => Err(e.into()),
        Some(Ok(DecodedItem::Payload(p))) => Ok(p),
        Some(Ok(DecodedItem::Bytes(_))) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected handshake payload, got bytes",
        )
        .into()),
    }
}

/// A future for receiving a Noise handshake message with an empty payload.
pub(crate) async fn recv_empty<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    let payload = recv(state).await?;
    if payload.get_size() != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected empty payload.").into());
    }

    Ok(())
}

/// A future for sending a Noise handshake message with an empty payload.
pub(crate) async fn send_empty<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncWrite + Unpin,
{
    state
        .io
        .send(StaticHandshakePayloadOrBytes::Payload(
            proto::NoiseHandshakePayload::default(),
        ))
        .await?;
    Ok(())
}

/// A future for receiving a Noise handshake message with a payload identifying the remote.
pub(crate) async fn recv_identity<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    let pb = recv(state).await?;
    state.id_remote_pubkey = Some(identity::PublicKey::try_decode_protobuf(&pb.identity_key)?);

    if !pb.identity_sig.is_empty() {
        state.dh_remote_pubkey_sig = Some(pb.identity_sig);
    }

    if let Some(extensions) = pb.extensions {
        state.remote_extensions = Some(extensions.into());
    }

    Ok(())
}

/// Send a Noise handshake message with a payload identifying the local node to the remote.
pub(crate) async fn send_identity<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut pb = proto::NoiseHandshakePayload {
        identity_key: state.identity.public.encode_protobuf(),
        ..Default::default()
    };

    pb.identity_sig.clone_from(&state.identity.signature);

    // If this is the responder then send WebTransport certhashes to initiator, if any.
    if state.io.codec().is_responder() {
        if let Some(ref certhashes) = state.responder_webtransport_certhashes {
            let ext = pb
                .extensions
                .get_or_insert_with(proto::NoiseExtensions::default);

            ext.webtransport_certhashes = certhashes
                .iter()
                .map(|hash| hash.to_bytes().into())
                .collect();
        }
    }

    state
        .io
        .send(StaticHandshakePayloadOrBytes::Payload(pb))
        .await?;

    Ok(())
}

/// Send the final KEM message in a post-quantum handshake (4th message).
pub(crate) async fn send_final_kem<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncWrite + Unpin,
{
    state
        .io
        .send(StaticHandshakePayloadOrBytes::Payload(
            proto::NoiseHandshakePayload::default(),
        ))
        .await?;
    Ok(())
}

/// Receive the final KEM message in a post-quantum handshake (4th message).
pub(crate) async fn recv_final_kem<T>(state: &mut State<T>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    let payload = recv(state).await?;
    if payload.get_size() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected empty payload for final KEM message.",
        )
        .into());
    }

    Ok(())
}
