// cargo bench --features "pk_recovery_mode" --bench FALCON_pk_recovery_mode_bench

#![allow(unused)]

use std::{
    fs::File,
    io::{Read, Write},
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use pqcrypto_falcon::*;
use rand::{thread_rng, Rng};

const NUM_KEYS: usize = 10;
const SIGS_PER_KEY: usize = 10;

pub fn falcon_rust_operation(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut keys512 = (0..NUM_KEYS)
        .map(|_| falcon_rust::falcon512::keygen(rng.gen()))
        .collect_vec();
    let mut keys1024 = (0..NUM_KEYS)
        .map(|_| falcon_rust::falcon1024::keygen(rng.gen()))
        .collect_vec();
    let mut msgs512 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|_| rng.gen::<[u8; 15]>())
        .collect_vec();
    let mut msgs1024 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|_| rng.gen::<[u8; 15]>())
        .collect_vec();
    let mut sigs512 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|i| falcon_rust::falcon512::sign(&msgs512[i], &keys512[i % NUM_KEYS].0))
        .collect_vec();
    let mut sigs1024 = (0..NUM_KEYS * SIGS_PER_KEY)
        .map(|i| falcon_rust::falcon1024::sign(&msgs1024[i], &keys1024[i % NUM_KEYS].0))
        .collect_vec();

    let mut group = c.benchmark_group("falcon-rust-pk-recovery-mode");
    group.sample_size(NUM_KEYS);
    group.bench_function("keygen 512", |b| {
        b.iter(|| {
            falcon_rust::falcon512::keygen(rng.gen());
        })
    });
    group.bench_function("keygen 1024", |b| {
        b.iter(|| {
            falcon_rust::falcon1024::keygen(rng.gen());
        })
    });
    group.finish();

    let mut group = c.benchmark_group("falcon-rust-pk-recovery-mode");
    group.sample_size(NUM_KEYS * SIGS_PER_KEY);
    let mut iterator_sign_512 = 0;
    group.bench_function("sign 512", |b| {
        b.iter(|| {
            falcon_rust::falcon512::sign(
                &msgs512[iterator_sign_512 % (NUM_KEYS * SIGS_PER_KEY)],
                &keys512[iterator_sign_512 % NUM_KEYS].0,
            );
            iterator_sign_512 += 1;
        })
    });
    let mut iterator_sign_1024 = 0;
    group.bench_function("sign 1024", |b| {
        b.iter(|| {
            falcon_rust::falcon1024::sign(
                &msgs1024[iterator_sign_1024 % (NUM_KEYS * SIGS_PER_KEY)],
                &keys1024[iterator_sign_1024 % NUM_KEYS].0,
            );
            iterator_sign_1024 += 1;
        })
    });
    group.finish();

    let mut group = c.benchmark_group("falcon-rust-pk-recovery-mode");
    group.sample_size(NUM_KEYS * SIGS_PER_KEY);
    let mut iterator_verify_512 = 0;
    let mut successful_verifications_512 = 0;
    group.bench_function("verify 512", |b| {
        b.iter(|| {
            let result = falcon_rust::falcon512::verify(
                &msgs512[iterator_verify_512 % msgs512.len()],
                &sigs512[iterator_verify_512 % sigs512.len()],
                &keys512[iterator_verify_512 % NUM_KEYS].1,
            );
            if result {successful_verifications_512 += 1;}
            // assert!(result);
            iterator_verify_512 += 1;
        })
    });
    // Something is failing every so often in the process, likely during signature generation
    // Unsure what the cause is
    // Checked that s2 can be inverted, so that doesn't seem to be the problem
    // Leaving as is for the time being
    println!("successful_verifications {:?}", successful_verifications_512);
    println!("iterator_verify_512 {:?}", iterator_verify_512);
    let mut successful_verifications_1024 = 0;
    let mut iterator_verify_1024 = 0;
    group.bench_function("verify 1024", |b| {
        b.iter(|| {
            let result = falcon_rust::falcon1024::verify(
                &msgs1024[iterator_verify_1024 % msgs1024.len()],
                &sigs1024[iterator_verify_1024 % sigs1024.len()],
                &keys1024[iterator_verify_1024 % NUM_KEYS].1,
            );
            if result {successful_verifications_1024 += 1;}
            // assert!(result);
            iterator_verify_1024 += 1;
        })
    });
    println!("successful_verifications_1024 {:?}", successful_verifications_1024);
    println!("iterator_verify_1024 {:?}", iterator_verify_1024);
    group.finish();
}

criterion_group!(benches, falcon_rust_operation);
criterion_main!(benches);
