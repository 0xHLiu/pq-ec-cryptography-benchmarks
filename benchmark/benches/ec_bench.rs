// cargo bench --bench ec_bench

#![allow(unused)]

use std::{
    fs::File,
    io::{Read, Write},
};

extern crate bitcoin_hashes;
extern crate secp256k1;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use pqcrypto_falcon::*;
use rand::{thread_rng, Rng};
use bitcoin_hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

const NUM_KEYS: usize = 10;
const SIGS_PER_KEY: usize = 10;

fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey: PublicKey,
) -> Result<bool, Error> {
    let msg= sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: SecretKey,
) -> Result<ecdsa::Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    // let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa(&msg, &seckey))
}

pub fn secp256k1_operation(c: &mut Criterion) {

    let secp = Secp256k1::new();

    let mut rng = thread_rng();
    let mut keys512 = (0..NUM_KEYS)
        .map(|_| secp.generate_keypair(&mut rng))
        .collect_vec();
    let mut msgs512 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|_| rng.gen::<[u8; 15]>())
        .collect_vec();
    let mut sigs512 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|i| sign(&secp, &msgs512[i], keys512[i % NUM_KEYS].0)
        .unwrap()
        .serialize_compact())
        .collect_vec();

    let mut group = c.benchmark_group("secp256k1");
    group.sample_size(NUM_KEYS);
    group.bench_function("keygen 512", |b| {
        b.iter(|| {
            secp.generate_keypair(&mut thread_rng());
        })
    });
    group.finish();

    let mut group = c.benchmark_group("secp256k1");
    group.sample_size(NUM_KEYS * SIGS_PER_KEY);
    let mut iterator_sign_512 = 0;
    group.bench_function("sign 512", |b| {
        b.iter(|| {
            sign(&secp,
                 &msgs512[iterator_sign_512 % (NUM_KEYS * SIGS_PER_KEY)],
                 keys512[iterator_sign_512 % NUM_KEYS].0,
            );
            iterator_sign_512 += 1;
        })
    });
    group.finish();

    let mut group = c.benchmark_group("secp256k1");
    group.sample_size(NUM_KEYS * SIGS_PER_KEY);
    let mut iterator_verify_512 = 0;
    group.bench_function("verify 512", |b| {
        b.iter(|| {
            assert!(verify(&secp,
                           &msgs512[iterator_verify_512 % msgs512.len()],
                           sigs512[iterator_verify_512 % sigs512.len()],
                           keys512[iterator_verify_512 % NUM_KEYS].1,
            )
                .unwrap());
            iterator_verify_512 += 1;
        })
    });
    group.finish();
}


criterion_group!(benches, secp256k1_operation);
criterion_main!(benches);
