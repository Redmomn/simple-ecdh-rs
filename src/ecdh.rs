use crate::KeyExchange;
use crypto_bigint::modular::{MontyForm, MontyParams, SafeGcdInverter};
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::subtle::ConstantTimeEq;
use crypto_bigint::{
    Concat, Encoding, Integer, Limb, NonZero, Odd, PrecomputeInverter, RandomMod, Split, Uint,
};
use md5::{Digest, Md5};
use std::ops::Add;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EcdhError {
    #[error("Invalid public key.")]
    InvalidPublicKey,
    #[error("Invalid secret key.")]
    InvalidSecretKey,
    #[error("Point is not on the curve.")]
    PointNotOnCurve,
}

#[derive(Debug, Clone)]
pub struct Ecdh<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    curve: EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>,
    secret: Uint<LIMBS>,
    public: EllipticPoint<LIMBS>,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    Ecdh<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    const SIZE: usize = LIMBS * Limb::BYTES;
    pub fn new(curve: EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>) -> Result<Self, EcdhError> {
        let mut ecdh = Ecdh {
            curve,
            secret: Uint::default(),
            public: EllipticPoint::default(),
        };
        ecdh.secret = Uint::<LIMBS>::random_mod(&mut OsRng, &ecdh.curve.n);
        ecdh.public = ecdh.create_public()?;
        Ok(ecdh)
    }

    pub fn new_with_secret<S: AsRef<[u8]>>(
        curve: EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>,
        secret: S,
    ) -> Result<Self, EcdhError> {
        let mut ecdh = Ecdh {
            curve,
            secret: Self::unpack_secret(secret)?,
            public: EllipticPoint::default(),
        };
        ecdh.public = ecdh.create_public()?;
        Ok(ecdh)
    }

    pub fn pack_public(&self, compress: bool) -> Result<Vec<u8>, EcdhError> {
        if compress {
            let mut result = vec![0u8; Self::SIZE + 1];
            result[0] = if self.public.y.is_even().into() {
                0x02
            } else {
                0x03
            };
            result[1..].copy_from_slice(Encoding::to_be_bytes(&self.public.x).as_ref());
            Ok(result)
        } else {
            let mut result = vec![0u8; Self::SIZE * 2 + 1];
            result[0] = 0x04;
            result[1..Self::SIZE + 1]
                .copy_from_slice(Encoding::to_be_bytes(&self.public.x).as_ref());
            result[Self::SIZE + 1..]
                .copy_from_slice(Encoding::to_be_bytes(&self.public.y).as_ref());
            Ok(result)
        }
    }

    pub fn pack_secret(&self) -> Result<Vec<u8>, EcdhError> {
        let mut result = vec![0u8; Self::SIZE + 4];
        result[3] = Self::SIZE as u8;
        result[4..].copy_from_slice(Encoding::to_be_bytes(&self.secret).as_ref());
        Ok(result)
    }

    fn pack_shared(&self, ec_shared: &EllipticPoint<LIMBS>, hash: bool) -> Vec<u8> {
        let x = Encoding::to_be_bytes(&ec_shared.x);
        if hash {
            Md5::digest(x.as_ref()[..self.curve.pack_size].as_ref()).to_vec()
        } else {
            x.as_ref().to_vec()
        }
    }

    fn unpack_public<P: AsRef<[u8]>>(
        &self,
        public_key: P,
    ) -> Result<EllipticPoint<LIMBS>, EcdhError> {
        let public_key = public_key.as_ref();
        if public_key.len() == Self::SIZE * 2 + 1 && public_key[0] == 0x04 {
            // Uncompressed format
            let x = Uint::<LIMBS>::from_be_slice(&public_key[1..Self::SIZE + 1]);
            let y = Uint::<LIMBS>::from_be_slice(&public_key[Self::SIZE + 1..]);
            let point = EllipticPoint::new(x, y);
            Ok(point)
        } else if public_key.len() == Self::SIZE + 1 {
            // Compressed format
            // find the y-coordinate from x-coordinate by y^2 = x^3 + ax + b
            let y_parity = public_key[0];
            if y_parity != 0x02 && y_parity != 0x03 {
                return Err(EcdhError::InvalidPublicKey);
            }
            let x = Uint::<LIMBS>::from_be_slice(&public_key[1..]);
            let x3 = x.mul_mod(&x, &self.curve.p).mul_mod(&x, &self.curve.p);
            let ax = self.curve.a.mul_mod(&x, &self.curve.p);
            let y2 = x3
                .add_mod(&ax, &self.curve.p)
                .add_mod(&self.curve.b, &self.curve.p);
            let tmp = self.curve.p.add(Uint::ONE).shr(2);
            let monty_params = MontyParams::new(Odd::new(*self.curve.p.as_ref()).unwrap());
            let monty_mod = MontyForm::new(&y2, monty_params);
            let y = monty_mod.pow(&tmp).retrieve();

            let y = if (y.is_even().into() && y_parity == 0x02)
                || (!bool::from(y.is_even()) && y_parity == 0x03)
            {
                y
            } else {
                self.curve.p.sub_mod(&y, &self.curve.p)
            };
            let point = EllipticPoint::new(x, y);
            Ok(point)
        } else {
            Err(EcdhError::InvalidPublicKey)
        }
    }

    fn unpack_secret<S: AsRef<[u8]>>(secret_key: S) -> Result<Uint<LIMBS>, EcdhError> {
        let secret_key = secret_key.as_ref();
        if secret_key.len() != Self::SIZE + 4 || secret_key[0..3] != [0, 0, Self::SIZE as u8] {
            return Err(EcdhError::InvalidSecretKey);
        }
        let secret = Uint::<LIMBS>::from_be_slice(&secret_key[4..]);
        Ok(secret)
    }

    fn create_public(&self) -> Result<EllipticPoint<LIMBS>, EcdhError> {
        self.create_shared(&self.curve.g)
    }

    fn create_shared(
        &self,
        public: &EllipticPoint<LIMBS>,
    ) -> Result<EllipticPoint<LIMBS>, EcdhError> {
        if !self.curve.check_on(public) {
            return Err(EcdhError::PointNotOnCurve);
        }
        // double-and-add algorithm
        let mut pr = EllipticPoint::default();
        let mut pa = public.clone();

        for i in 0..LIMBS * Limb::BITS as usize - 1 {
            if self.secret.bit(i as u32).into() {
                pr = self.curve.point_add(&pr, &pa);
            }
            pa = self.curve.point_add(&pa, &pa);
        }
        Ok(pr)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize> KeyExchange
    for Ecdh<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    type Error = EcdhError;

    fn key_exchange<T: AsRef<[u8]>>(&self, ec_pub: T, hash: bool) -> Result<Vec<u8>, EcdhError> {
        let shared = self.create_shared(&self.unpack_public(ec_pub)?)?;
        Ok(self.pack_shared(&shared, hash))
    }
}

#[derive(Debug, Clone)]
pub struct EllipticCurve<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    pub(crate) p: NonZero<Uint<LIMBS>>,
    pub(crate) a: Uint<LIMBS>,
    pub(crate) b: Uint<LIMBS>,
    pub(crate) g: EllipticPoint<LIMBS>,
    pub(crate) n: NonZero<Uint<LIMBS>>,
    #[allow(dead_code)]
    pub(crate) h: usize,
    pub(crate) pack_size: usize,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    fn check_on(&self, point: &EllipticPoint<LIMBS>) -> bool {
        // y^2 = x^3 + ax + b
        let y2 = point.y.mul_mod(&point.y, &self.p);
        let x3 = point
            .x
            .mul_mod(&point.x, &self.p)
            .mul_mod(&point.x, &self.p);
        let ax = self.a.mul_mod(&point.x, &self.p);
        let rhs = x3.add_mod(&ax, &self.p).add_mod(&self.b, &self.p);
        y2 == rhs
    }

    fn point_add(
        &self,
        p: &EllipticPoint<LIMBS>,
        q: &EllipticPoint<LIMBS>,
    ) -> EllipticPoint<LIMBS> {
        if p.is_default() {
            return q.clone();
        }
        if q.is_default() {
            return p.clone();
        }

        // p.x == q.x
        let x_eq = p.x.ct_eq(&q.x);
        // p.y == q.y
        let y_eq = p.y.ct_eq(&q.y);

        let p_eq_q = x_eq & y_eq;
        // p + (-q) = O <==> x_p = x_q and y_p = -y_q mod p
        let p_neg_q = x_eq & !y_eq & p.y.ct_eq(&q.y.neg_mod(&self.p));
        if bool::from(p_neg_q) {
            return EllipticPoint::default();
        }

        let lambda = if bool::from(p_eq_q) {
            // λ = (3*x1^2 + a) / (2*y1) mod p
            let three_x1_sq =
                p.x.mul_mod(&p.x, &self.p)
                    .mul_mod(&Uint::from(3u8), &self.p);
            let numerator = three_x1_sq.add_mod(&self.a, &self.p);
            let denominator = p.y.mul_mod(&Uint::from(2u8), &self.p);
            let inv_den = denominator.inv_mod(&self.p).unwrap();
            numerator.mul_mod(&inv_den, &self.p)
        } else {
            // λ = (y2 - y1) / (x2 - x1) mod p
            let numerator = q.y.sub_mod(&p.y, &self.p);
            let denominator = q.x.sub_mod(&p.x, &self.p);
            let inv_den = denominator.inv_mod(&self.p).unwrap();
            numerator.mul_mod(&inv_den, &self.p)
        };

        // x3 = λ^2 - x1 - x2 mod p
        let lambda_sq = lambda.mul_mod(&lambda, &self.p);
        let x3 = lambda_sq.sub_mod(&p.x, &self.p).sub_mod(&q.x, &self.p);

        // y3 = λ(x1 - x3) - y1 mod p
        let x1_sub_x3 = p.x.sub_mod(&x3, &self.p);
        let y3 = lambda.mul_mod(&x1_sub_x3, &self.p).sub_mod(&p.y, &self.p);

        EllipticPoint::new(x3, y3)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EllipticPoint<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub(crate) x: Uint<LIMBS>,
    pub(crate) y: Uint<LIMBS>,
}

impl<const LIMBS: usize> EllipticPoint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(x: Uint<LIMBS>, y: Uint<LIMBS>) -> Self {
        Self { x, y }
    }

    pub fn is_default(&self) -> bool {
        self.x == Uint::ZERO && self.y == Uint::ZERO
    }
}

impl<const LIMBS: usize> Default for EllipticPoint<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            x: Uint::ZERO,
            y: Uint::ZERO,
        }
    }
}
