use criterion::{Criterion, criterion_group, criterion_main};
use pprof::criterion::{Output, PProfProfiler};
use simple_ecdh::Ecdh;
use simple_ecdh::curve::PRIME256V1;
use std::hint::black_box;

fn ecdh_keygen_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    c.bench_function("keygen", |b| {
        b.iter(|| {
            // 使用 black_box 来防止编译器优化掉这个函数调用
            let _alice = black_box(Ecdh::new(curve_p256.clone())).unwrap();
        });
    });
}

criterion_group! {
    name = keygen;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = ecdh_keygen_benchmark
}

criterion_main!(keygen);
