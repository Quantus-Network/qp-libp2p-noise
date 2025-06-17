//! Test to verify that the PQ XX handshake pattern works in isolation
//! This helps debug whether the issue is with the pattern itself or libp2p integration

use clatter::{
    crypto::{cipher::ChaChaPoly, hash::Sha256, kem::rust_crypto_ml_kem::MlKem768},
    handshakepattern::noise_pqxx,
    traits::{Handshaker, Kem},
    PqHandshake,
};

#[test]
fn test_pq_xx_handshake_isolation() {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // Generate static keypairs for both parties
    let alice_static = MlKem768::genkey(&mut rng_alice).unwrap();
    let bob_static = MlKem768::genkey(&mut rng_bob).unwrap();

    // Create handshake instances
    let mut alice = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqxx(),
        &[],  // empty prologue
        true, // alice is initiator
        Some(alice_static),
        None, // no ephemeral key
        None, // no remote static key known
        None, // no remote ephemeral key known
        &mut rng_alice,
    )
    .expect("Alice handshake creation should succeed");

    let mut bob = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqxx(),
        &[],   // empty prologue
        false, // bob is responder
        Some(bob_static),
        None, // no ephemeral key
        None, // no remote static key known
        None, // no remote ephemeral key known
        &mut rng_bob,
    )
    .expect("Bob handshake creation should succeed");

    // Message buffers - make them large enough for PQ keys
    let mut buf_alice = [0u8; 8192];
    let mut buf_bob = [0u8; 8192];

    println!("Starting PQ XX handshake...");
    println!(
        "Initial state - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 1: Alice -> Bob (E)
    println!("Message 1: Alice sends ephemeral key");
    assert!(
        alice.is_write_turn(),
        "Alice should be in write state for message 1"
    );
    let msg1_len = alice
        .write_message(&[], &mut buf_alice)
        .expect("Alice should be able to write message 1");
    println!("Message 1 length: {} bytes", msg1_len);
    println!(
        "After msg1 write - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    assert!(
        !bob.is_write_turn(),
        "Bob should be in read state for message 1"
    );
    let _payload1_len = bob
        .read_message(&buf_alice[..msg1_len], &mut buf_bob)
        .expect("Bob should be able to read message 1");
    println!(
        "After msg1 read - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 2: Bob -> Alice (Ekem, S)
    println!("Message 2: Bob sends ephemeral KEM + static key");
    assert!(
        bob.is_write_turn(),
        "Bob should be in write state for message 2"
    );
    let msg2_len = bob
        .write_message(&[], &mut buf_bob)
        .expect("Bob should be able to write message 2");
    println!("Message 2 length: {} bytes", msg2_len);
    println!(
        "After msg2 write - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    assert!(
        !alice.is_write_turn(),
        "Alice should be in read state for message 2"
    );
    let _payload2_len = alice
        .read_message(&buf_bob[..msg2_len], &mut buf_alice)
        .expect("Alice should be able to read message 2");
    println!(
        "After msg2 read - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 3: Alice -> Bob (Skem, S)
    println!("Message 3: Alice sends static KEM + static key");
    assert!(
        alice.is_write_turn(),
        "Alice should be in write state for message 3"
    );
    let msg3_len = alice
        .write_message(&[], &mut buf_alice)
        .expect("Alice should be able to write message 3");
    println!("Message 3 length: {} bytes", msg3_len);
    println!(
        "After msg3 write - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    assert!(
        !bob.is_write_turn(),
        "Bob should be in read state for message 3"
    );
    let _payload3_len = bob
        .read_message(&buf_alice[..msg3_len], &mut buf_bob)
        .expect("Bob should be able to read message 3");
    println!(
        "After msg3 read - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Check if we need a 4th message (Bob -> Alice: Skem)
    if !alice.is_finished() || !bob.is_finished() {
        println!("Handshake not finished after 3 messages, trying 4th message...");

        if bob.is_write_turn() {
            println!("Message 4: Bob sends static KEM");
            let msg4_len = bob
                .write_message(&[], &mut buf_bob)
                .expect("Bob should be able to write message 4");
            println!("Message 4 length: {} bytes", msg4_len);
            println!(
                "After msg4 write - Alice finished: {}, Bob finished: {}",
                alice.is_finished(),
                bob.is_finished()
            );

            if !alice.is_write_turn() {
                let _payload4_len = alice
                    .read_message(&buf_bob[..msg4_len], &mut buf_alice)
                    .expect("Alice should be able to read message 4");
                println!(
                    "After msg4 read - Alice finished: {}, Bob finished: {}",
                    alice.is_finished(),
                    bob.is_finished()
                );
            }
        } else if alice.is_write_turn() {
            println!("Message 4: Alice sends something");
            let msg4_len = alice
                .write_message(&[], &mut buf_alice)
                .expect("Alice should be able to write message 4");
            println!("Message 4 length: {} bytes", msg4_len);

            let _payload4_len = bob
                .read_message(&buf_alice[..msg4_len], &mut buf_bob)
                .expect("Bob should be able to read message 4");
            println!(
                "After msg4 read - Alice finished: {}, Bob finished: {}",
                alice.is_finished(),
                bob.is_finished()
            );
        }
    }

    // Check that both handshakes are finished
    println!(
        "Final check - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );
    assert!(alice.is_finished(), "Alice handshake should be finished");
    assert!(bob.is_finished(), "Bob handshake should be finished");

    println!("Handshake completed successfully!");

    // Finalize handshakes to get transport states
    let mut alice_transport = alice.finalize().expect("Alice finalize should succeed");
    let mut bob_transport = bob.finalize().expect("Bob finalize should succeed");

    // Test transport encryption/decryption
    let plaintext = b"Hello from Alice to Bob via PQ XX!";
    let mut ciphertext = [0u8; 1024];
    let mut decrypted = [0u8; 1024];

    // Alice encrypts
    let ct_len = alice_transport
        .send(plaintext, &mut ciphertext)
        .expect("Alice should be able to encrypt");

    // Bob decrypts
    let pt_len = bob_transport
        .receive(&ciphertext[..ct_len], &mut decrypted)
        .expect("Bob should be able to decrypt");

    assert_eq!(&decrypted[..pt_len], plaintext);
    println!("Transport encryption/decryption works!");

    // Test the reverse direction
    let reply = b"Hello back from Bob!";
    let reply_ct_len = bob_transport
        .send(reply, &mut ciphertext)
        .expect("Bob should be able to encrypt reply");

    let reply_pt_len = alice_transport
        .receive(&ciphertext[..reply_ct_len], &mut decrypted)
        .expect("Alice should be able to decrypt reply");

    assert_eq!(&decrypted[..reply_pt_len], reply);
    println!("Bidirectional transport works!");

    println!("✅ PQ XX pattern works correctly in isolation!");
}

#[test]
fn test_pq_xx_message_sizes() {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    let alice_static = MlKem768::genkey(&mut rng_alice).unwrap();
    let bob_static = MlKem768::genkey(&mut rng_bob).unwrap();

    let mut alice = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqxx(),
        &[],
        true,
        Some(alice_static),
        None,
        None,
        None,
        &mut rng_alice,
    )
    .unwrap();

    let mut bob = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqxx(),
        &[],
        false,
        Some(bob_static),
        None,
        None,
        None,
        &mut rng_bob,
    )
    .unwrap();

    let mut buf_alice = [0u8; 8192];
    let mut buf_bob = [0u8; 8192];

    // Test message sizes to understand buffer requirements
    let msg1_len = alice.write_message(&[], &mut buf_alice).unwrap();
    println!("Message 1 (E) size: {} bytes", msg1_len);

    let _payload1_len = bob
        .read_message(&buf_alice[..msg1_len], &mut buf_bob)
        .unwrap();

    let msg2_len = bob.write_message(&[], &mut buf_bob).unwrap();
    println!("Message 2 (Ekem, S) size: {} bytes", msg2_len);

    let _payload2_len = alice
        .read_message(&buf_bob[..msg2_len], &mut buf_alice)
        .unwrap();

    let msg3_len = alice.write_message(&[], &mut buf_alice).unwrap();
    println!("Message 3 (Skem, S) size: {} bytes", msg3_len);

    // Verify that our EXTRA_ENCRYPT_SPACE is sufficient
    const EXTRA_ENCRYPT_SPACE: usize = 4096;
    assert!(
        msg1_len <= EXTRA_ENCRYPT_SPACE,
        "Message 1 ({} bytes) exceeds EXTRA_ENCRYPT_SPACE ({})",
        msg1_len,
        EXTRA_ENCRYPT_SPACE
    );
    assert!(
        msg2_len <= EXTRA_ENCRYPT_SPACE,
        "Message 2 ({} bytes) exceeds EXTRA_ENCRYPT_SPACE ({})",
        msg2_len,
        EXTRA_ENCRYPT_SPACE
    );
    assert!(
        msg3_len <= EXTRA_ENCRYPT_SPACE,
        "Message 3 ({} bytes) exceeds EXTRA_ENCRYPT_SPACE ({})",
        msg3_len,
        EXTRA_ENCRYPT_SPACE
    );

    println!("✅ All message sizes fit within EXTRA_ENCRYPT_SPACE");
}

#[test]
fn test_pq_nn_comparison() {
    // Test the working NN pattern for comparison
    use clatter::handshakepattern::noise_pqnn;

    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // NN doesn't use static keys
    let mut alice = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqnn(),
        &[],
        true, // alice is initiator
        None, // no static key for NN
        None,
        None,
        None,
        &mut rng_alice,
    )
    .expect("Alice NN handshake creation should succeed");

    let mut bob = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqnn(),
        &[],
        false, // bob is responder
        None,  // no static key for NN
        None,
        None,
        None,
        &mut rng_bob,
    )
    .expect("Bob NN handshake creation should succeed");

    let mut buf_alice = [0u8; 8192];
    let mut buf_bob = [0u8; 8192];

    println!("Testing NN pattern for comparison...");

    // Message 1: Alice -> Bob (E)
    println!("NN Message 1: Alice sends ephemeral key");
    let msg1_len = alice.write_message(&[], &mut buf_alice).unwrap();
    println!("NN Message 1 length: {} bytes", msg1_len);

    let _payload1_len = bob
        .read_message(&buf_alice[..msg1_len], &mut buf_bob)
        .unwrap();
    println!(
        "After NN msg1 - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 2: Bob -> Alice (Ekem)
    println!("NN Message 2: Bob sends ephemeral KEM");
    let msg2_len = bob.write_message(&[], &mut buf_bob).unwrap();
    println!("NN Message 2 length: {} bytes", msg2_len);

    let _payload2_len = alice
        .read_message(&buf_bob[..msg2_len], &mut buf_alice)
        .unwrap();
    println!(
        "After NN msg2 - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // NN should be finished after 2 messages
    assert!(alice.is_finished(), "Alice NN handshake should be finished");
    assert!(bob.is_finished(), "Bob NN handshake should be finished");

    println!("✅ NN pattern works correctly and finishes after 2 messages");
}

#[test]
fn test_pq_nx_pattern() {
    // Test the NX pattern which should be 3 messages like libp2p expects
    use clatter::handshakepattern::noise_pqnx;

    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // Generate static keypair for Bob (responder needs static key in NX)
    let bob_static = MlKem768::genkey(&mut rng_bob).unwrap();

    let mut alice = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqnx(),
        &[],
        true, // alice is initiator
        None, // alice has no static key in NX
        None,
        None,
        None,
        &mut rng_alice,
    )
    .expect("Alice NX handshake creation should succeed");

    let mut bob = PqHandshake::<MlKem768, MlKem768, ChaChaPoly, Sha256, _>::new(
        noise_pqnx(),
        &[],
        false,            // bob is responder
        Some(bob_static), // bob has static key in NX
        None,
        None,
        None,
        &mut rng_bob,
    )
    .expect("Bob NX handshake creation should succeed");

    let mut buf_alice = [0u8; 8192];
    let mut buf_bob = [0u8; 8192];

    println!("Testing NX pattern (3 messages)...");

    // Message 1: Alice -> Bob (E)
    println!("NX Message 1: Alice sends ephemeral key");
    let msg1_len = alice.write_message(&[], &mut buf_alice).unwrap();
    println!("NX Message 1 length: {} bytes", msg1_len);

    let _payload1_len = bob
        .read_message(&buf_alice[..msg1_len], &mut buf_bob)
        .unwrap();
    println!(
        "After NX msg1 - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 2: Bob -> Alice (Ekem, S)
    println!("NX Message 2: Bob sends ephemeral KEM + static key");
    let msg2_len = bob.write_message(&[], &mut buf_bob).unwrap();
    println!("NX Message 2 length: {} bytes", msg2_len);

    let _payload2_len = alice
        .read_message(&buf_bob[..msg2_len], &mut buf_alice)
        .unwrap();
    println!(
        "After NX msg2 - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // Message 3: Alice -> Bob (Skem)
    println!("NX Message 3: Alice sends static KEM");
    let msg3_len = alice.write_message(&[], &mut buf_alice).unwrap();
    println!("NX Message 3 length: {} bytes", msg3_len);

    let _payload3_len = bob
        .read_message(&buf_alice[..msg3_len], &mut buf_bob)
        .unwrap();
    println!(
        "After NX msg3 - Alice finished: {}, Bob finished: {}",
        alice.is_finished(),
        bob.is_finished()
    );

    // NX should be finished after 3 messages
    assert!(alice.is_finished(), "Alice NX handshake should be finished");
    assert!(bob.is_finished(), "Bob NX handshake should be finished");

    println!("✅ NX pattern works correctly and finishes after 3 messages!");

    // Test transport mode
    let mut alice_transport = alice.finalize().expect("Alice finalize should succeed");
    let mut bob_transport = bob.finalize().expect("Bob finalize should succeed");

    let plaintext = b"Hello via PQ NX!";
    let mut ciphertext = [0u8; 1024];
    let mut decrypted = [0u8; 1024];

    let ct_len = alice_transport.send(plaintext, &mut ciphertext).unwrap();
    let pt_len = bob_transport
        .receive(&ciphertext[..ct_len], &mut decrypted)
        .unwrap();

    assert_eq!(&decrypted[..pt_len], plaintext);
    println!("NX transport encryption/decryption works!");
}
