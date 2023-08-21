#![no_main]
// If you want to try std support, also update the guest Cargo.toml file

use core::hint::black_box;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn verify(verifying_key: VerifyingKey, message: &[u8], signature: Signature) {
    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("Ed25519 signature verification failed");
}

pub fn main() {
    // Decode the verifying key, message, and signature from the inputs.
    let (encoded_verifying_key, message, signature_bytes): ([u8; 32], Vec<u8>, Vec<u8>) =
        env::read();

    let verifying_key = VerifyingKey::from_bytes(&encoded_verifying_key).unwrap();
    let signature: Signature = Signature::from_slice(&signature_bytes).unwrap();

    // Verify the signature, panicking if verification fails.
    black_box(verify(
        black_box(verifying_key),
        black_box(&message),
        black_box(signature),
    ));

    let start = env::get_cycle_count();

    black_box(verify(
        black_box(verifying_key),
        black_box(&message),
        black_box(signature),
    ));

    let end = env::get_cycle_count();
    println!("Verification: {} cycles", end - start);

    // Commit to the journal the verifying key and message that was signed.
    // env::commit(&(encoded_verifying_key, message));
}
