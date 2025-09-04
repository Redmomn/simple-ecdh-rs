use criterion::{Criterion, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use simple_ecdh::{Ecdh, KeyExchange};
use simple_ecdh::curve::PRIME256V1;
use std::hint::black_box;

fn ecdh_key_exchange_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    let alice = Ecdh::new(curve_p256.clone()).unwrap();
    let bob_public_key = Ecdh::new(curve_p256.clone())
        .unwrap()
        .pack_public(false)
        .unwrap();

    c.bench_function("key_exchange", |b| {
        b.iter(|| {
            let _shared_key = black_box(alice.key_exchange(bob_public_key.clone(), false)).unwrap();
        });
    });
}
criterion_group! {
    name = key_exchange;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = ecdh_key_exchange_benchmark
}

criterion_main!(key_exchange);
