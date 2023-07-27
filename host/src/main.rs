// TODO: Update the name of the method loaded by the prover. E.g., if the method
// is `multiply`, replace `METHOD_NAME_ELF` with `MULTIPLY_ELF` and replace
// `METHOD_NAME_ID` with `MULTIPLY_ID`
use methods::{ED25519_VERIFY_ELF, ED25519_VERIFY_ID};
use risc0_zkvm::serde::{from_slice, to_vec};
use risc0_zkvm::{default_executor_from_elf, Executor, ExecutorEnv};

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use risc0_zkvm::SessionReceipt;

fn prove_ed25519_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> SessionReceipt {
    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&(verifying_key.as_bytes(), message, signature.to_vec())).unwrap())
        .build()
        .unwrap();

    let mut exec = default_executor_from_elf(env, ED25519_VERIFY_ELF).unwrap();
    let session = exec.run().unwrap();
    session.prove().unwrap()
}

fn main() {
    let mut csprng = OsRng {};
    let keypair: SigningKey = SigningKey::generate(&mut csprng);
    let message: &[u8] = b"This is a test of the tsunami alert system.";
    let signature: Signature = keypair.sign(message);

    let receipt = prove_ed25519_verification(&keypair.verifying_key(), message, &signature);

    // TODO: Implement code for transmitting or serializing the receipt for
    // other parties to verify here

    // Optional: Verify receipt to confirm that recipients will also be able to
    // verify your receipt
    receipt.verify(ED25519_VERIFY_ID).unwrap();
}
