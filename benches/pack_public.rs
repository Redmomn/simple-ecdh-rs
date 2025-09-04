use criterion::{Criterion, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use simple_ecdh::Ecdh;
use simple_ecdh::curve::PRIME256V1;
use std::hint::black_box;

fn ecdh_pack_public_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    let ecdh = Ecdh::new(curve_p256.clone()).unwrap();
    c.bench_function("pack_public", |b| {
        b.iter(|| {
            // black_box 确保输入参数不会被优化
            let _public_key = black_box(ecdh.pack_public(false)).unwrap();
        });
    });
}

criterion_group! {
    name = pack_public;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = ecdh_pack_public_benchmark
}

criterion_main!(pack_public);
