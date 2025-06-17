// Copyright 2020 Parity Technologies (UK) Ltd.
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

//! Provides a [`Codec`] type implementing the [`Encoder`] and [`Decoder`] traits.
//!
//! Alongside a [`asynchronous_codec::Framed`] this provides a [Sink](futures::Sink)
//! and [Stream](futures::Stream) for length-delimited Noise protocol messages.

use std::{io, mem::size_of};

use asynchronous_codec::{Decoder, Encoder};
use bytes::{Buf, Bytes, BytesMut};
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};

use super::handshake::proto;
use crate::{
    protocol::{ClatterSession, ClatterTransport, PublicKey},
    Error,
};

/// Max. size of a noise message.
const MAX_NOISE_MSG_LEN: usize = 65535;
/// Space given to the encryption buffer to hold key material.
/// Increased to accommodate ML-KEM768: pubkey (1184) + ciphertext (1088) + overhead
const EXTRA_ENCRYPT_SPACE: usize = 4096;
/// Max. length for Noise protocol message payloads.
pub(crate) const MAX_FRAME_LEN: usize = MAX_NOISE_MSG_LEN - EXTRA_ENCRYPT_SPACE;
static_assertions::const_assert! {
    MAX_FRAME_LEN + EXTRA_ENCRYPT_SPACE <= MAX_NOISE_MSG_LEN
}

/// Codec holds the noise session state and acts as a medium for
/// encoding and decoding length-delimited session messages.
pub(crate) enum Codec {
    Handshake {
        state: ClatterSession,
        write_buffer: BytesMut,
        encrypt_buffer: BytesMut,
    },
    Transport {
        state: ClatterTransport,
        write_buffer: BytesMut,
        encrypt_buffer: BytesMut,
    },
}

impl Codec {
    pub(crate) fn new_handshake(state: ClatterSession) -> Self {
        Codec::Handshake {
            state,
            write_buffer: BytesMut::default(),
            encrypt_buffer: BytesMut::default(),
        }
    }

    pub(crate) fn new_transport(state: ClatterTransport) -> Self {
        Codec::Transport {
            state,
            write_buffer: BytesMut::default(),
            encrypt_buffer: BytesMut::default(),
        }
    }
}

impl Codec {
    /// Checks if the session was started in the `initiator` role.
    pub(crate) fn is_initiator(&self) -> bool {
        match self {
            Codec::Handshake { state, .. } => state.is_initiator(),
            Codec::Transport { .. } => false, // Transport doesn't have this concept
        }
    }

    /// Checks if the session was started in the `responder` role.
    pub(crate) fn is_responder(&self) -> bool {
        !self.is_initiator()
    }

    /// Converts the underlying Noise session from handshake to transport state,
    /// including the static DH [`PublicKey`] of the remote if received.
    ///
    /// If the Noise protocol session state does not permit transitioning to
    /// transport mode because the handshake is incomplete, an error is returned.
    ///
    /// An error is also returned if the remote's static DH key is not present or
    /// cannot be parsed, as that indicates a fatal handshake error.
    pub(crate) fn into_transport(self) -> Result<(PublicKey, Codec), Error> {
        match self {
            Codec::Handshake {
                state,
                write_buffer,
                encrypt_buffer,
            } => {
                let dh_remote_pubkey = state.get_remote_static().ok_or_else(|| {
                    Error::Io(io::Error::new(
                        io::ErrorKind::Other,
                        "expect key to always be present at end of handshake",
                    ))
                })?;

                let dh_remote_pubkey = PublicKey::from_slice(&dh_remote_pubkey)?;
                let transport_state = state.into_transport_mode()?;

                let codec = Codec::Transport {
                    state: transport_state,
                    write_buffer,
                    encrypt_buffer,
                };

                Ok((dh_remote_pubkey, codec))
            }
            Codec::Transport { .. } => Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "already in transport mode",
            ))),
        }
    }
}

impl Encoder for Codec {
    type Error = io::Error;
    type Item = StaticHandshakePayloadOrBytes;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match (self, item) {
            (
                Codec::Handshake {
                    state,
                    write_buffer,
                    encrypt_buffer,
                },
                StaticHandshakePayloadOrBytes::Payload(payload),
            ) => {
                let item_size = payload.get_size();

                write_buffer.resize(item_size, 0);
                let mut writer = Writer::new(&mut write_buffer[..item_size]);
                payload
                    .write_message(&mut writer)
                    .expect("Protobuf encoding to succeed");

                encrypt(
                    &write_buffer[..item_size],
                    dst,
                    &mut *encrypt_buffer,
                    |item, buffer| {
                        state.write_message(item, buffer).map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Clatter error: {:?}", e),
                            )
                        })
                    },
                )?;

                Ok(())
            }
            (
                Codec::Transport {
                    state,
                    encrypt_buffer,
                    ..
                },
                StaticHandshakePayloadOrBytes::Bytes(bytes),
            ) => encrypt(&bytes, dst, &mut *encrypt_buffer, |item, buffer| {
                state.write_message(item, buffer).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Clatter error: {:?}", e),
                    )
                })
            }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mismatched codec state and item type",
            )),
        }
    }
}

pub(crate) enum HandshakePayloadOrBytes<'a> {
    Payload(&'a proto::NoiseHandshakePayload),
    Bytes(&'a [u8]),
}

// Static versions for Encoder
pub(crate) enum StaticHandshakePayloadOrBytes {
    Payload(proto::NoiseHandshakePayload),
    Bytes(Vec<u8>),
}

impl Decoder for Codec {
    type Error = io::Error;
    type Item = DecodedItem;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            Codec::Handshake { state, .. } => {
                let cleartext = match decrypt(src, |ciphertext, decrypt_buffer| {
                    state.read_message(ciphertext, decrypt_buffer).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Clatter error: {:?}", e),
                        )
                    })
                })? {
                    None => return Ok(None),
                    Some(cleartext) => cleartext,
                };

                let mut reader = BytesReader::from_bytes(&cleartext[..]);
                let pb = proto::NoiseHandshakePayload::from_reader(&mut reader, &cleartext)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Failed decoding handshake payload",
                        )
                    })?;

                Ok(Some(DecodedItem::Payload(pb)))
            }
            Codec::Transport { state, .. } => {
                let cleartext = decrypt(src, |ciphertext, decrypt_buffer| {
                    state.read_message(ciphertext, decrypt_buffer).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Clatter error: {:?}", e),
                        )
                    })
                })?;

                Ok(cleartext.map(DecodedItem::Bytes))
            }
        }
    }
}

pub(crate) enum DecodedItem {
    Payload(proto::NoiseHandshakePayload),
    Bytes(Bytes),
}

/// Encrypts the given cleartext to `dst`.
///
/// This is a standalone function to allow us reusing the `encrypt_buffer` and to use to across
/// different session states of the noise protocol.
fn encrypt(
    cleartext: &[u8],
    dst: &mut BytesMut,
    encrypt_buffer: &mut BytesMut,
    encrypt_fn: impl FnOnce(&[u8], &mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    tracing::trace!("Encrypting {} bytes", cleartext.len());

    encrypt_buffer.resize(cleartext.len() + EXTRA_ENCRYPT_SPACE, 0);
    let n = encrypt_fn(cleartext, encrypt_buffer)?;

    tracing::trace!("Outgoing ciphertext has {n} bytes");

    encode_length_prefixed(&encrypt_buffer[..n], dst);

    Ok(())
}

/// Encrypts the given ciphertext.
///
/// This is a standalone function so we can use it across different session states of the noise
/// protocol. In case `ciphertext` does not contain enough bytes to decrypt the entire frame,
/// `Ok(None)` is returned.
fn decrypt(
    ciphertext: &mut BytesMut,
    decrypt_fn: impl FnOnce(&[u8], &mut [u8]) -> io::Result<usize>,
) -> io::Result<Option<Bytes>> {
    let Some(ciphertext) = decode_length_prefixed(ciphertext) else {
        return Ok(None);
    };

    tracing::trace!("Incoming ciphertext has {} bytes", ciphertext.len());

    let mut decrypt_buffer = BytesMut::zeroed(ciphertext.len());
    let n = decrypt_fn(&ciphertext, &mut decrypt_buffer)?;

    tracing::trace!("Decrypted cleartext has {n} bytes");

    Ok(Some(decrypt_buffer.split_to(n).freeze()))
}

const U16_LENGTH: usize = size_of::<u16>();

fn encode_length_prefixed(src: &[u8], dst: &mut BytesMut) {
    dst.reserve(U16_LENGTH + src.len());
    dst.extend_from_slice(&(src.len() as u16).to_be_bytes());
    dst.extend_from_slice(src);
}

fn decode_length_prefixed(src: &mut BytesMut) -> Option<Bytes> {
    if src.len() < size_of::<u16>() {
        return None;
    }

    let mut len_bytes = [0u8; U16_LENGTH];
    len_bytes.copy_from_slice(&src[..U16_LENGTH]);
    let len = u16::from_be_bytes(len_bytes) as usize;

    if src.len() - U16_LENGTH >= len {
        // Skip the length header we already read.
        src.advance(U16_LENGTH);
        Some(src.split_to(len).freeze())
    } else {
        None
    }
}
