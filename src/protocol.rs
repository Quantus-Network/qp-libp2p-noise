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

//! Components of a Noise protocol using Clatter.

use clatter::{bytearray::ByteArray, traits::Kem, transportstate::TransportState};
use libp2p_identity as identity;
use rand::{Rng as _, SeedableRng};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

use crate::Error;

/// Prefix of static key signatures for domain separation.
pub(crate) const STATIC_KEY_DOMAIN: &str = "noise-libp2p-static-key:";

/// Clatter session that manages handshake state
pub(crate) struct ClatterSession {
    inner: ClatterSessionInner,
}

enum ClatterSessionInner {
    Classical(ClassicalSession),
    PostQuantum(PostQuantumSession),
}

struct ClassicalSession {
    // We store RNG in a Box to get a stable address
    rng: Box<rand::rngs::StdRng>,
    // The handshake borrows from the boxed RNG
    handshake: Option<
        clatter::NqHandshake<
            'static,
            clatter::crypto::dh::X25519,
            clatter::crypto::cipher::ChaChaPoly,
            clatter::crypto::hash::Sha256,
            rand::rngs::StdRng,
        >,
    >,
    static_keypair: Option<
        clatter::KeyPair<
            <clatter::crypto::dh::X25519 as clatter::traits::Dh>::PubKey,
            <clatter::crypto::dh::X25519 as clatter::traits::Dh>::PrivateKey,
        >,
    >,
    prologue: Vec<u8>,
    is_initiator: bool,
}

struct PostQuantumSession {
    rng: Box<rand::rngs::StdRng>,
    handshake: Option<
        clatter::PqHandshake<
            'static,
            clatter::crypto::kem::rust_crypto_ml_kem::MlKem768,
            clatter::crypto::kem::rust_crypto_ml_kem::MlKem768,
            clatter::crypto::cipher::ChaChaPoly,
            clatter::crypto::hash::Sha256,
            rand::rngs::StdRng,
        >,
    >,
    static_keypair: Option<
        clatter::KeyPair<
            <clatter::crypto::kem::rust_crypto_ml_kem::MlKem768 as clatter::traits::Kem>::PubKey,
            <clatter::crypto::kem::rust_crypto_ml_kem::MlKem768 as clatter::traits::Kem>::SecretKey,
        >,
    >,
    prologue: Vec<u8>,
    is_initiator: bool,
}

impl ClatterSession {
    /// Create a new clatter session
    pub(crate) fn new(
        prologue: &[u8],
        use_post_quantum: bool,
        is_initiator: bool,
        dh_keys: &AuthenticKeypair,
    ) -> Result<Self, Error> {
        let inner = if use_post_quantum {
            // For PQ, use the existing ML-KEM keys from the authenticated keypair
            let kem_secret = <clatter::crypto::kem::rust_crypto_ml_kem::MlKem768 as clatter::traits::Kem>::SecretKey::from_slice(
                dh_keys.keypair.secret.as_ref()
            );
            let kem_public = <clatter::crypto::kem::rust_crypto_ml_kem::MlKem768 as clatter::traits::Kem>::PubKey::from_slice(
                dh_keys.keypair.public.as_ref()
            );

            let static_keypair = clatter::KeyPair {
                public: kem_public,
                secret: kem_secret,
            };

            ClatterSessionInner::PostQuantum(PostQuantumSession {
                rng: Box::new(rand::rngs::StdRng::from_entropy()),
                handshake: None,
                static_keypair: Some(static_keypair),
                prologue: prologue.to_vec(),
                is_initiator,
            })
        } else {
            // Convert libp2p DH keys to clatter format
            let dh_secret = dh_keys.keypair.secret.as_ref();
            let dh_public = dh_keys.keypair.public.as_ref();

            let clatter_secret =
                <clatter::crypto::dh::X25519 as clatter::traits::Dh>::PrivateKey::from_slice(
                    dh_secret,
                );
            let clatter_public =
                <clatter::crypto::dh::X25519 as clatter::traits::Dh>::PubKey::from_slice(dh_public);

            let static_keypair = clatter::KeyPair {
                public: clatter_public,
                secret: clatter_secret,
            };

            ClatterSessionInner::Classical(ClassicalSession {
                rng: Box::new(rand::rngs::StdRng::from_entropy()),
                handshake: None,
                static_keypair: Some(static_keypair),
                prologue: prologue.to_vec(),
                is_initiator,
            })
        };

        Ok(Self { inner })
    }

    fn ensure_handshake_initialized(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            ClatterSessionInner::Classical(session) => {
                if session.handshake.is_none() {
                    use clatter::{
                        crypto::{cipher::ChaChaPoly, dh::X25519, hash::Sha256},
                        handshakepattern::noise_xx,
                        NqHandshake,
                    };

                    // Get a mutable reference to the boxed RNG
                    let rng_ptr = session.rng.as_mut() as *mut rand::rngs::StdRng;

                    // SAFETY: We're creating a 'static reference to the RNG.
                    // This is safe because:
                    // 1. The RNG is stored in a Box, so it has a stable address
                    // 2. The handshake will not outlive the session struct
                    // 3. We only create one handshake per session
                    let rng_ref: &'static mut rand::rngs::StdRng = unsafe { &mut *rng_ptr };

                    let handshake = NqHandshake::<X25519, ChaChaPoly, Sha256, _>::new(
                        noise_xx(),
                        &session.prologue,
                        session.is_initiator,
                        session.static_keypair.clone(),
                        None,
                        None,
                        None,
                        rng_ref,
                    )
                    .map_err(|e| {
                        Error::Clatter(format!("Failed to create classical handshake: {:?}", e))
                    })?;

                    session.handshake = Some(handshake);
                }
            }
            ClatterSessionInner::PostQuantum(session) => {
                if session.handshake.is_none() {
                    use clatter::{
                        crypto::{
                            cipher::ChaChaPoly, hash::Sha256, kem::rust_crypto_ml_kem::MlKem768,
                        },
                        handshakepattern::noise_pqxx,
                        PqHandshake,
                    };

                    let rng_ptr = session.rng.as_mut() as *mut rand::rngs::StdRng;
                    let rng_ref: &'static mut rand::rngs::StdRng = unsafe { &mut *rng_ptr };

                    let handshake = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
                        noise_pqxx(),
                        &session.prologue,
                        session.is_initiator,
                        session.static_keypair.clone(),
                        None,
                        None,
                        None,
                        rng_ref,
                    )
                    .map_err(|e| {
                        Error::Clatter(format!("Failed to create PQ handshake: {:?}", e))
                    })?;

                    session.handshake = Some(handshake);
                }
            }
        }
        Ok(())
    }

    /// Write a handshake message
    pub(crate) fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        self.ensure_handshake_initialized()?;

        use clatter::traits::Handshaker;
        match &mut self.inner {
            ClatterSessionInner::Classical(session) => {
                let handshake = session.handshake.as_mut().unwrap();
                handshake
                    .write_message(payload, message)
                    .map_err(|e| Error::Clatter(format!("Classical write failed: {:?}", e)))
            }
            ClatterSessionInner::PostQuantum(session) => {
                let handshake = session.handshake.as_mut().unwrap();
                handshake
                    .write_message(payload, message)
                    .map_err(|e| Error::Clatter(format!("PQ write failed: {:?}", e)))
            }
        }
    }

    /// Read a handshake message
    pub(crate) fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, Error> {
        self.ensure_handshake_initialized()?;

        use clatter::traits::Handshaker;
        match &mut self.inner {
            ClatterSessionInner::Classical(session) => {
                let handshake = session.handshake.as_mut().unwrap();
                handshake
                    .read_message(message, payload)
                    .map_err(|e| Error::Clatter(format!("Classical read failed: {:?}", e)))
            }
            ClatterSessionInner::PostQuantum(session) => {
                let handshake = session.handshake.as_mut().unwrap();
                handshake
                    .read_message(message, payload)
                    .map_err(|e| Error::Clatter(format!("PQ read failed: {:?}", e)))
            }
        }
    }

    /// Check if this is an initiator
    pub(crate) fn is_initiator(&self) -> bool {
        match &self.inner {
            ClatterSessionInner::Classical(session) => {
                if let Some(handshake) = &session.handshake {
                    use clatter::traits::Handshaker;
                    handshake.is_initiator()
                } else {
                    session.is_initiator
                }
            }
            ClatterSessionInner::PostQuantum(session) => {
                if let Some(handshake) = &session.handshake {
                    use clatter::traits::Handshaker;
                    handshake.is_initiator()
                } else {
                    session.is_initiator
                }
            }
        }
    }

    /// Get the remote's static public key
    pub(crate) fn get_remote_static(&self) -> Option<Vec<u8>> {
        use clatter::traits::Handshaker;
        match &self.inner {
            ClatterSessionInner::Classical(session) => session
                .handshake
                .as_ref()?
                .get_remote_static()
                .map(|k| k.as_slice().to_vec()),
            ClatterSessionInner::PostQuantum(session) => session
                .handshake
                .as_ref()?
                .get_remote_static()
                .map(|k| k.as_slice().to_vec()),
        }
    }

    /// Check if the handshake is finished
    pub(crate) fn is_finished(&self) -> bool {
        use clatter::traits::Handshaker;
        match &self.inner {
            ClatterSessionInner::Classical(session) => session
                .handshake
                .as_ref()
                .map_or(false, |h| h.is_finished()),
            ClatterSessionInner::PostQuantum(session) => session
                .handshake
                .as_ref()
                .map_or(false, |h| h.is_finished()),
        }
    }

    /// Convert to transport state
    pub(crate) fn into_transport_mode(mut self) -> Result<ClatterTransport, Error> {
        use clatter::traits::Handshaker;

        self.ensure_handshake_initialized()?;

        match self.inner {
            ClatterSessionInner::Classical(mut session) => {
                let handshake = session.handshake.take().unwrap();
                let transport = handshake.finalize().map_err(|e| {
                    Error::Clatter(format!("Failed to finalize classical handshake: {:?}", e))
                })?;
                Ok(ClatterTransport::Classical(Box::new(transport)))
            }
            ClatterSessionInner::PostQuantum(mut session) => {
                let handshake = session.handshake.take().unwrap();
                let transport = handshake.finalize().map_err(|e| {
                    Error::Clatter(format!("Failed to finalize PQ handshake: {:?}", e))
                })?;
                Ok(ClatterTransport::PostQuantum(Box::new(transport)))
            }
        }
    }
}

/// Transport state after handshake completion
pub(crate) enum ClatterTransport {
    Classical(
        Box<TransportState<clatter::crypto::cipher::ChaChaPoly, clatter::crypto::hash::Sha256>>,
    ),
    PostQuantum(
        Box<TransportState<clatter::crypto::cipher::ChaChaPoly, clatter::crypto::hash::Sha256>>,
    ),
}

impl ClatterTransport {
    /// Write a transport message
    pub(crate) fn write_message(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            ClatterTransport::Classical(transport) => transport
                .send(plaintext, ciphertext)
                .map_err(|e| Error::Clatter(format!("Classical transport write failed: {:?}", e))),
            ClatterTransport::PostQuantum(transport) => transport
                .send(plaintext, ciphertext)
                .map_err(|e| Error::Clatter(format!("PQ transport write failed: {:?}", e))),
        }
    }

    /// Read a transport message
    pub(crate) fn read_message(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            ClatterTransport::Classical(transport) => transport
                .receive(ciphertext, plaintext)
                .map_err(|e| Error::Clatter(format!("Classical transport read failed: {:?}", e))),
            ClatterTransport::PostQuantum(transport) => transport
                .receive(ciphertext, plaintext)
                .map_err(|e| Error::Clatter(format!("PQ transport read failed: {:?}", e))),
        }
    }
}

/// A keypair that supports both classical (X25519) and post-quantum (ML-KEM) keys.
#[derive(Clone)]
pub(crate) struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

/// A DH keypair that is authentic w.r.t. a [`identity::PublicKey`].
#[derive(Clone)]
pub(crate) struct AuthenticKeypair {
    pub(crate) keypair: Keypair,
    pub(crate) identity: KeypairIdentity,
}

/// The associated public identity of a DH keypair.
#[derive(Clone)]
pub(crate) struct KeypairIdentity {
    /// The public identity key.
    pub(crate) public: identity::PublicKey,
    /// The signature over the public DH key.
    pub(crate) signature: Vec<u8>,
}

impl Keypair {
    /// The secret key of the DH keypair.
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Turn this keypair into an [`AuthenticKeypair`] by signing the public
    /// key with the given [`identity::Keypair`].
    pub(crate) fn into_authentic(
        self,
        id_keys: &identity::Keypair,
    ) -> Result<AuthenticKeypair, Error> {
        let sig = id_keys.sign(&[STATIC_KEY_DOMAIN.as_bytes(), self.public.as_ref()].concat())?;

        let identity = KeypairIdentity {
            public: id_keys.public(),
            signature: sig,
        };

        Ok(AuthenticKeypair {
            keypair: self,
            identity,
        })
    }

    /// Create a new X25519 keypair (for classical mode and backwards compatibility).
    pub(crate) fn new() -> Keypair {
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut sk_bytes);
        let sk = SecretKey(sk_bytes.to_vec());
        sk_bytes.zeroize();
        Self::from(sk)
    }

    /// Create a new ML-KEM768 keypair (for post-quantum mode).
    pub(crate) fn new_ml_kem() -> Keypair {
        let mut rng = rand::thread_rng();
        let keypair = clatter::crypto::kem::rust_crypto_ml_kem::MlKem768::genkey(&mut rng)
            .expect("ML-KEM key generation should not fail");

        let secret = SecretKey(keypair.secret.as_slice().to_vec());
        let public = PublicKey(keypair.public.as_slice().to_vec());

        Keypair { secret, public }
    }
}

/// Secret key that supports both classical (32-byte) and post-quantum (variable-size) keys.
#[derive(Clone)]
pub(crate) struct SecretKey(Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey(vec![0u8; 32]) // Default to X25519 size for compatibility
    }
}

/// Public key that supports both classical (32-byte) and post-quantum (variable-size) keys.
#[derive(Clone, PartialEq)]
pub(crate) struct PublicKey(Vec<u8>);

impl PublicKey {
    pub(crate) fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        // Accept any non-empty key size to support both X25519 (32 bytes) and ML-KEM (1184 bytes)
        if slice.is_empty() {
            return Err(Error::InvalidLength);
        }

        Ok(PublicKey(slice.to_vec()))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey(vec![0u8; 32]) // Default to X25519 size for compatibility
    }
}

impl Default for Keypair {
    fn default() -> Self {
        Self::new()
    }
}

/// Promote a secret key into a keypair (works for X25519 keys only).
impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        if secret.0.len() == 32 {
            // X25519 case
            let mut sk_array = [0u8; 32];
            sk_array.copy_from_slice(&secret.0);
            let public_bytes = x25519(sk_array, X25519_BASEPOINT_BYTES);
            let public = PublicKey(public_bytes.to_vec());
            Keypair { secret, public }
        } else {
            panic!("From<SecretKey> only supports X25519 (32-byte) keys. Use Keypair::new() for ML-KEM keys.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clatter_session_creation_works() {
        let keypair = Keypair::new();
        let id_keys = identity::Keypair::generate_ed25519();
        let auth_keypair = keypair.into_authentic(&id_keys).unwrap();

        let alice = ClatterSession::new(b"shared knowledge", false, true, &auth_keypair).unwrap();
        let bob = ClatterSession::new(b"shared knowledge", false, false, &auth_keypair).unwrap();

        assert!(alice.is_initiator());
        assert!(!bob.is_initiator());
    }

    #[test]
    fn pq_session_creation_works() {
        let keypair = Keypair::new_ml_kem();
        let id_keys = identity::Keypair::generate_ed25519();
        let auth_keypair = keypair.into_authentic(&id_keys).unwrap();

        let alice = ClatterSession::new(b"shared knowledge", true, true, &auth_keypair).unwrap();
        let bob = ClatterSession::new(b"shared knowledge", true, false, &auth_keypair).unwrap();

        assert!(alice.is_initiator());
        assert!(!bob.is_initiator());
    }
}
