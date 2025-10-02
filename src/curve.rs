use crate::ecdh::{EllipticCurve, EllipticPoint};
use crypto_bigint::{NonZero, U192, U256, Uint};

pub const PRIME256V1: EllipticCurve<4, 8, 6> = EllipticCurve {
    p: NonZero::<Uint<_>>::new_unwrap(U256::from_be_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    )),
    a: U256::from_be_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
    b: U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    g: EllipticPoint {
        x: U256::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        y: U256::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    },
    n: NonZero::<Uint<_>>::new_unwrap(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    )),
    h: 1,
    pack_size: 16,
};

pub const SECP192K1: EllipticCurve<3, 6, 5> = EllipticCurve {
    p: NonZero::<Uint<_>>::new_unwrap(U192::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffeffffee37",
    )),
    a: U192::from_be_hex("000000000000000000000000000000000000000000000000"),
    b: U192::from_be_hex("000000000000000000000000000000000000000000000003"),
    g: EllipticPoint {
        x: U192::from_be_hex("db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"),
        y: U192::from_be_hex("9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
    },
    n: NonZero::<Uint<_>>::new_unwrap(U192::from_be_hex(
        "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    )),
    h: 1,
    pack_size: 24,
};
