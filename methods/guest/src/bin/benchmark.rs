// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use core::hint::black_box;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
// use curve25519_dalek::field::FieldElement;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;
use elliptic_curve::bigint::{Encoding, U256};
use hex_literal::hex;
use risc0_zkvm::guest::env;

/// Basic function for benchmarking an operation.
fn bench<T>(name: &str, func: impl Fn() -> T) {
    // Run the inner function twice, only logging the cycles in the second run, in
    // order to exclude paged-in operations from the benchmark count.
    black_box(func());

    let start = env::get_cycle_count();

    black_box(func());

    let end = env::get_cycle_count();
    println!("{}: {} cycles", name, end - start)
}

// /// Benchmark key operations in the secp256k1 base field.
// fn benchmark_field() {
//     println!("Field operations:");
//     let x = black_box(
//         FieldElement::from_bytes(
//             &hex!("EC08EAC2CBCEFE58E61038DCA45BA2B4A56BDF05A3595EBEE1BCFC488889C1CF").into(),
//         )
//         .unwrap(),
//     );
//     let y = black_box(
//         FieldElement::from_bytes(
//             &hex!("9FC3E90D2FAD03C8669F437A26374FA694CA76A7913C5E016322EBAA5C7616C5").into(),
//         )
//         .unwrap(),
//     );

//     bench("add", || x.add(&y));
//     bench("mul", || x.mul(&y));
//     bench("mul_single", || x.mul_single(42));
//     bench("square", || x.square());
//     bench("negate", || x.negate(0));
//     bench("invert", || x.invert().unwrap());
// }

/// Benchmark operations in the secp256k1 scalar field.
fn benchmark_scalar() {
    println!("");
    println!("Scalar operations:");
    let x = black_box(Scalar::from_bytes_mod_order(
        U256::from_be_bytes(hex!(
            "2A3F714FCDDEA4984F228C4D1DBD41A79B470B1546C68F6BB268A04AA0394BAC"
        ))
        .to_le_bytes(),
    ));
    let y = black_box(Scalar::from_bytes_mod_order(
        U256::from_be_bytes(hex!(
            "98973615F3B819529D885BBED9A69BC66A678D00289A8B1F3A0FF19801C10CDD"
        ))
        .to_le_bytes(),
    ));

    bench("add", || x + y);
    bench("mul", || x * y);
    bench("square", || x * x);
    bench("negate", || -x);
    bench("invert", || x.invert());
}

/// Benchmark secp256k1 elliptic curve group operations.
fn benchmark_group() {
    println!("");
    println!("Group operations:");
    let x = black_box(Scalar::from_bytes_mod_order(
        U256::from_be_bytes(hex!(
            "2a3f714fcddea4984f228c4d1dbd41a79b470b1546c68f6bb268a04aa0394bac"
        ))
        .to_le_bytes(),
    ));
    let y = black_box(Scalar::from_bytes_mod_order(
        U256::from_be_bytes(hex!(
            "2a3f714fcddea4984f228c4d1dbd41a79b470b1546c68f6bb268a04aa0394bac"
        ))
        .to_le_bytes(),
    ));

    // NOTE: Accounts for >95% of the total cycle count for ECDSA verification.
    bench("vartime_double_scalar_mul_basepoint", || {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&x, &ED25519_BASEPOINT_POINT, &y);
    });
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // benchmark_field();
    benchmark_scalar();
    benchmark_group();
}
