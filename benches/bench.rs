use criterion::{Criterion, criterion_group, criterion_main};
use simple_ecdh::curve::PRIME256V1;
use simple_ecdh::{Ecdh, KeyExchange};
use std::hint::black_box;

fn ecdh_keygen_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    c.bench_function("ECDH 密钥生成", |b| {
        b.iter(|| {
            // 使用 black_box 来防止编译器优化掉这个函数调用
            let _alice = black_box(Ecdh::new(curve_p256.clone())).unwrap();
        });
    });
}

fn ecdh_pack_public_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    let ecdh = Ecdh::new(curve_p256.clone()).unwrap();
    c.bench_function("ECDH 公钥打包", |b| {
        b.iter(|| {
            // black_box 确保输入参数不会被优化
            let _public_key = black_box(ecdh.pack_public(false)).unwrap();
        });
    });
}

fn ecdh_key_exchange_benchmark(c: &mut Criterion) {
    let curve_p256 = &PRIME256V1.clone();
    let alice = Ecdh::new(curve_p256.clone()).unwrap();
    let bob_public_key = Ecdh::new(curve_p256.clone())
        .unwrap()
        .pack_public(false)
        .unwrap();

    c.bench_function("ECDH 密钥交换", |b| {
        b.iter(|| {
            let _shared_key = black_box(alice.key_exchange(bob_public_key.clone(), false)).unwrap();
        });
    });
}

// 组合所有基准测试组
criterion_group!(
    benches,
    ecdh_keygen_benchmark,
    ecdh_pack_public_benchmark,
    ecdh_key_exchange_benchmark
);
criterion_main!(benches);
