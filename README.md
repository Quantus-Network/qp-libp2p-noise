# libp2p-noise-pqc

A post-quantum cryptography enabled fork of `libp2p-noise` that provides [Noise protocol framework][noise] support for libp2p with both classical and post-quantum cryptographic algorithms.

## Overview

This crate is a drop-in replacement for the original `libp2p-noise` that swaps out the [snow](https://github.com/mcginty/snow) library with [clatter](https://github.com/rot256/clatter), enabling support for post-quantum cryptography alongside traditional cryptographic methods.

### Key Changes from libp2p-noise

- **Cryptographic Backend**: Replaced `snow` with `clatter` for Noise protocol implementation
- **Post-Quantum Support**: Added ML-KEM768 (formerly Kyber768) support via the `ml-kem` feature
- **Dual Algorithm Support**: Supports both X25519 (classical) and ML-KEM768 (post-quantum) key exchange
- **Drop-in Compatibility**: Maintains the same API surface as the original `libp2p-noise`

## Features

- **Classical Cryptography**: X25519 key exchange with ChaCha20-Poly1305 encryption
- **Post-Quantum Cryptography**: ML-KEM768 key encapsulation with ChaCha20-Poly1305 encryption
- **Noise XX Handshake Pattern**: Secure mutual authentication handshake
- **WebTransport Support**: Certificate hash validation for WebTransport connections
- **Configurable Prologue**: Support for custom handshake prologues

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
libp2p-noise = { path = "path/to/libp2p-noise-pqc" }
```

### Basic Example

```rust
use libp2p_core::{Transport, upgrade, transport::MemoryTransport};
use libp2p_noise as noise;
use libp2p_identity as identity;

let id_keys = identity::Keypair::generate_ed25519();
let noise = noise::Config::new(&id_keys).unwrap();
let builder = MemoryTransport::default()
    .upgrade(upgrade::Version::V1)
    .authenticate(noise);
```

### Post-Quantum Configuration

By default, when the `ml-kem` feature is enabled, the library automatically uses post-quantum cryptography:

```rust
use libp2p_noise as noise;
use libp2p_identity as identity;

let id_keys = identity::Keypair::generate_ed25519();

// Automatically uses ML-KEM768 when ml-kem feature is enabled
let noise_config = noise::Config::new(&id_keys).unwrap();

// Or explicitly enable post-quantum crypto
let pq_config = noise::Config::new(&id_keys)
    .unwrap()
    .with_post_quantum();
```

### Classical Cryptography Only

To use only classical X25519 cryptography, disable the `ml-kem` feature:

```toml
[dependencies]
libp2p-noise = { path = "path/to/libp2p-noise-pqc", default-features = false }
```

## Feature Flags

- `ml-kem` (default): Enables ML-KEM768 post-quantum cryptography support
- When disabled, falls back to classical X25519 key exchange

## Cryptographic Algorithms

### Classical Mode (X25519)
- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman
- **Cipher**: ChaCha20-Poly1305
- **Hash**: SHA-256
- **Handshake Pattern**: Noise XX

### Post-Quantum Mode (ML-KEM768)
- **Key Encapsulation**: ML-KEM768 (NIST standardized)
- **Cipher**: ChaCha20-Poly1305
- **Hash**: SHA-256
- **Handshake Pattern**: Noise PQXX (post-quantum variant)

## Security Considerations

### Algorithm Selection

- **Default Behavior**: ML-KEM768 is used by default when the `ml-kem` feature is enabled
- **Interoperability**: Both peers must use the same cryptographic mode for successful handshakes
- **Performance**: Classical X25519 provides better performance, while ML-KEM768 offers quantum resistance

## Performance Characteristics

| Algorithm | Key Size | Handshake Messages | Performance | Quantum Resistance |
|-----------|----------|-------------------|-------------|-------------------|
| X25519 | 32 bytes | 3 messages | Higher | No |
| ML-KEM768 | 1184 bytes | 4 messages | Lower | Yes |

## Implementation Details

### Handshake Patterns

- **XX Pattern (Classical)**: `-> e, <- e, ee, -> s, se, <- s, es`
- **PQXX Pattern (Post-Quantum)**: `-> e, <- e, ee, -> s, se, <- s, es, -> kem, <- kem`

### Unsafe Code and Lifetime Management

This implementation contains minimal unsafe code to work around lifetime constraints in the clatter library. 
The unsafe code is used specifically for RNG (Random Number Generator) lifetime management:

```rust
let rng_ref: &'static mut rand::rngs::StdRng = unsafe { &mut *rng_ptr };
```

**Why this is necessary:**
- Clatter's handshake constructors require a `&'static mut` reference to an RNG
- Our RNG is owned by the session struct, which doesn't have a static lifetime
- This is essentially a design limitation in clatter's API that forces this workaround

**Why this is safe:**
1. **Stable Memory Location**: The RNG is stored in a `Box<StdRng>`, giving it a stable heap address
2. **Controlled Lifetime**: The handshake object never outlives the session that owns the RNG
3. **Single Ownership**: We only create one handshake per session, preventing multiple mutable references
4. **Contained Scope**: The unsafe operation is isolated and well-documented

This represents the only unsafe code in the implementation and is a direct consequence of clatter's lifetime requirements rather than a design choice in our implementation.

## Testing

Run the test suite:

```bash
cargo test
```

Run tests with post-quantum crypto disabled:

```bash
cargo test --no-default-features
```

## Logging

The library uses the `log` crate for debugging information. Enable logging to see which cryptographic mode is being used:

```rust
env_logger::init();
// Will log: "🔊 Using pqc (ml-kem) ⚛ for noise!" or "🔊 Using x25519 ╭╯ for noise"
```

## Contributing

This project is based on the original `libp2p-noise` implementation. When contributing:

1. Ensure compatibility with the original libp2p-noise API
2. Test both classical and post-quantum modes
3. Follow the existing code style and patterns
4. Update tests and documentation accordingly

## License

MIT License - see the original libp2p-noise for full license details.

## Acknowledgments

- Original `libp2p-noise` implementation by Parity Technologies
- [clatter](https://github.com/rot256/clatter) library for post-quantum Noise protocol support
- NIST for standardizing post-quantum cryptographic algorithms

[noise]: https://noiseprotocol.org/
