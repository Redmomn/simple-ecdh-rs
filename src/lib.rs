pub mod curve;

use md5::{Digest, Md5};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{FromBytes, One, Signed, Zero};
use rand::RngCore;
use std::fmt;
use std::io::Write;
use std::ops::Neg;

pub trait KeyExchange {
    type Error;

    fn key_exchange<T: AsRef<[u8]>>(
        &self,
        public: T,
        hash: bool,
    ) -> std::result::Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub enum EcdhError {
    InvalidPublicKey,
    InvalidSecretKey,
    PointNotOnCurve,
    InverseDoesNotExist,
    IOError(std::io::Error),
}

impl fmt::Display for EcdhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EcdhError::InvalidPublicKey => write!(f, "Invalid public key."),
            EcdhError::InvalidSecretKey => write!(f, "Invalid secret key."),
            EcdhError::PointNotOnCurve => write!(f, "Point is not on the curve."),
            EcdhError::InverseDoesNotExist => write!(f, "Modular inverse does not exist."),
            EcdhError::IOError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for EcdhError {}

impl From<std::io::Error> for EcdhError {
    fn from(err: std::io::Error) -> Self {
        EcdhError::IOError(err)
    }
}

pub type Result<T> = std::result::Result<T, EcdhError>;

#[derive(Debug, Clone)]
pub struct Ecdh {
    curve: EllipticCurve,
    secret: BigInt,
    public: EllipticPoint,
}

impl Ecdh {
    pub fn new(curve: EllipticCurve) -> Result<Self> {
        let mut ecdh = Ecdh {
            curve,
            secret: BigInt::default(),
            public: EllipticPoint::default(),
        };
        ecdh.secret = ecdh.create_secret()?;
        ecdh.public = ecdh.create_public()?;
        Ok(ecdh)
    }

    pub fn new_with_secret<T: AsRef<[u8]>>(curve: EllipticCurve, secret: T) -> Result<Self> {
        let mut ecdh = Ecdh {
            curve,
            secret: BigInt::default(),
            public: EllipticPoint::default(),
        };
        ecdh.secret = Self::unpack_secret(secret.as_ref())?;
        ecdh.public = ecdh.create_public()?;
        Ok(ecdh)
    }

    pub fn pack_public(&self, compress: bool) -> Result<Vec<u8>> {
        if compress {
            let mut result = vec![0u8; self.curve.size + 1];
            result[0] = if self.public.y.is_even() ^ self.public.y.is_negative() {
                0x02
            } else {
                0x03
            };
            (&mut result[1..]).write_all(self.public.x.to_bytes_be().1.as_slice())?;
            Ok(result)
        } else {
            let mut result = vec![0u8; self.curve.size * 2 + 1];
            result[0] = 0x04;
            (&mut result[1..]).write_all(self.public.x.to_bytes_be().1.as_slice())?;
            (&mut result[self.curve.size + 1..])
                .write_all(self.public.y.to_bytes_be().1.as_slice())?;
            Ok(result)
        }
    }

    pub fn pack_secret(&self) -> Result<Vec<u8>> {
        let raw_length = self.secret.to_bytes_be().1.len();
        let mut result = vec![0u8; raw_length + 4];
        (&mut result[4..]).write_all(self.secret.to_bytes_be().1.as_slice())?;
        result[3] = raw_length as u8;
        Ok(result)
    }

    fn pack_shared(&self, ec_shared: &EllipticPoint, hash: bool) -> Vec<u8> {
        let x = ec_shared.x.to_bytes_be().1;
        if hash {
            Md5::digest(x.as_slice()[..self.curve.pack_size].as_ref()).to_vec()
        } else {
            x
        }
    }

    fn unpack_public<T: AsRef<[u8]>>(&self, public_key: T) -> Result<EllipticPoint> {
        let length = public_key.as_ref().len();
        if length != self.curve.size * 2 + 1 && length != self.curve.size + 1 {
            return Err(EcdhError::InvalidPublicKey);
        }
        if public_key.as_ref()[0] == 0x04 {
            Ok(EllipticPoint::new(
                BigInt::from_bytes_be(
                    Sign::Plus,
                    public_key.as_ref()[1..self.curve.size + 1].as_ref(),
                ),
                BigInt::from_bytes_be(
                    Sign::Plus,
                    public_key.as_ref()[self.curve.size + 1..].as_ref(),
                ),
            ))
        } else {
            // find the y-coordinate from x-coordinate by y^2 = x^3 + ax + b
            let px = BigInt::from_bytes_be(Sign::Plus, public_key.as_ref()[1..].as_ref());
            let x3 = px.modpow(&BigInt::from(3), &self.curve.p);
            let ax = (&px * &self.curve.a) % &self.curve.p;
            let right = (&x3 + &ax + &self.curve.b) % &self.curve.p;

            let tmp = (&self.curve.p + 1) >> 2;
            let mut py = right.modpow(&tmp, &self.curve.p);
            if !(py.is_even() && public_key.as_ref()[0] == 0x02
                || !py.is_even() && public_key.as_ref()[0] == 0x03)
            {
                py = &self.curve.p - py;
            }
            Ok(EllipticPoint::new(px, py))
        }
    }

    fn unpack_secret<T: AsRef<[u8]>>(ec_secret: T) -> Result<BigInt> {
        let length = ec_secret.as_ref().len() - 4;
        if length != ec_secret.as_ref()[3] as usize {
            return Err(EcdhError::InvalidSecretKey);
        }
        Ok(BigInt::from_be_bytes(
            ec_secret.as_ref()[4..length + 4].as_ref(),
        ))
    }

    fn create_public(&self) -> Result<EllipticPoint> {
        self.create_shared(&self.secret, &self.curve.g)
    }

    fn create_secret(&self) -> Result<BigInt> {
        let mut rng = rand::thread_rng();
        let mut arr = vec![0u8; self.curve.size];
        loop {
            rng.fill_bytes(&mut arr);
            let result = BigInt::from_be_bytes(arr.as_slice());
            if result >= BigInt::one() && result < self.curve.n {
                return Ok(result);
            }
        }
    }

    fn create_shared(
        &self,
        ec_secret: &BigInt,
        ec_public: &EllipticPoint,
    ) -> Result<EllipticPoint> {
        if ec_secret % &self.curve.n == BigInt::ZERO || ec_public.is_default() {
            return Ok(EllipticPoint::default());
        }
        if ec_secret.is_negative() {
            return self.create_shared(&-ec_secret, ec_public);
        }
        if !self.curve.check_on(ec_public) {
            return Err(EcdhError::PointNotOnCurve);
        }

        let mut pr = EllipticPoint::default();
        let mut pa = ec_public.clone();
        let mut ps = ec_secret.clone();
        while ps > BigInt::ZERO {
            if (&ps & BigInt::one()) > BigInt::ZERO {
                pr = self.point_add(&pr, &pa)?;
            }
            pa = self.point_add(&pa, &pa)?;
            ps >>= 1;
        }
        if !self.curve.check_on(&pr) {
            return Err(EcdhError::PointNotOnCurve);
        }
        Ok(pr)
    }

    fn point_add(&self, p1: &EllipticPoint, p2: &EllipticPoint) -> Result<EllipticPoint> {
        if p1.is_default() {
            return Ok(p2.clone());
        };
        if p2.is_default() {
            return Ok(p1.clone());
        };
        if !self.curve.check_on(p1) || !self.curve.check_on(p2) {
            return Err(EcdhError::PointNotOnCurve);
        }

        let (x1, x2, y1, y2) = (&p1.x, &p2.x, &p1.y, &p2.y);

        let m = if x1 == x2 {
            if y1 == y2 {
                (3 * x1 * x1 + &self.curve.a) * mod_inverse(&(y1 << 1), &self.curve.p)?
            } else {
                return Ok(EllipticPoint::default());
            }
        } else {
            (y1 - y2) * mod_inverse(&(x1 - x2), &self.curve.p)?
        };
        let xr = mod_positive(&(&m * &m - x1 - x2), &self.curve.p);
        let yr = mod_positive(&(&m * (x1 - &xr) - y1), &self.curve.p);
        let pr = EllipticPoint::new(xr, yr);
        if !self.curve.check_on(&pr) {
            return Err(EcdhError::PointNotOnCurve);
        }
        Ok(pr)
    }
}

impl KeyExchange for Ecdh {
    type Error = EcdhError;

    fn key_exchange<T: AsRef<[u8]>>(&self, ec_pub: T, hash: bool) -> Result<Vec<u8>> {
        let shared = self.create_shared(&self.secret, &self.unpack_public(ec_pub)?)?;
        Ok(self.pack_shared(&shared, hash))
    }
}

fn mod_inverse(a: &BigInt, b: &BigInt) -> Result<BigInt> {
    if a.is_negative() {
        return Ok(b - mod_inverse(&-a, b)?);
    }
    if a.gcd(b) != BigInt::one() {
        return Err(EcdhError::InverseDoesNotExist);
    }
    Ok(a.modpow(&(b - 2), b))
}

fn mod_positive(a: &BigInt, b: &BigInt) -> BigInt {
    let result = a % b;
    if result.is_negative() {
        result + b
    } else {
        result
    }
}

#[derive(Debug, Clone)]
pub struct EllipticCurve {
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
    pub g: EllipticPoint,
    pub n: BigInt,
    // h: BigInt,
    pub size: usize,
    pub pack_size: usize,
}

impl EllipticCurve {
    pub fn check_on(&self, point: &EllipticPoint) -> bool {
        // ((&point.y.pow(2) - &point.x.pow(3) - &self.a * &point.x - &self.b) % &self.p) == BigInt::zero()
        let lhs = point.y.modpow(&BigInt::from(2), &self.p); // y² mod p
        let rhs = (point.x.modpow(&BigInt::from(3), &self.p)  // x³ mod p
            + (&self.a * &point.x) % &self.p
            + &self.b)
            % &self.p;
        lhs == rhs
    }
}

#[derive(Debug, Clone)]
pub struct EllipticPoint {
    x: BigInt,
    y: BigInt,
}

impl EllipticPoint {
    pub fn new(x: BigInt, y: BigInt) -> EllipticPoint {
        Self { x, y }
    }

    pub fn is_default(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }
}

impl Default for EllipticPoint {
    fn default() -> EllipticPoint {
        EllipticPoint {
            x: BigInt::ZERO,
            y: BigInt::ZERO,
        }
    }
}

impl Neg for EllipticPoint {
    type Output = EllipticPoint;
    fn neg(self) -> EllipticPoint {
        Self {
            x: -self.x,
            y: -self.y,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_shared() -> Result<()> {
        let ec_pub = EllipticPoint {
            x: BigInt::from_slice(
                Sign::Plus,
                &[
                    3633889942, 4104206661, 770388896, 1996717441, 1671708914, 4173129445,
                    3777774151, 1796723186,
                ],
            ),
            y: BigInt::from_slice(
                Sign::Plus,
                &[
                    935285237, 3417718888, 1798397646, 734933847, 2081398294, 2397563722,
                    4263149467, 1340293858,
                ],
            ),
        };
        let ec_sec = BigInt::from_slice(
            Sign::Plus,
            &[
                2792767394, 3497172710, 1652332542, 1637215680, 2069543466, 3042786051, 1983615641,
                1413039311,
            ],
        );
        let ecdh = Ecdh {
            curve: curve::PRIME256V1.clone(),
            public: EllipticPoint::default(),
            secret: BigInt::from_slice(
                Sign::Plus,
                &[
                    2792767394, 3497172710, 1652332542, 1637215680, 2069543466, 3042786051,
                    1983615641, 1413039311,
                ],
            ),
        };
        let shared = ecdh.create_shared(&ec_sec, &ec_pub)?;
        assert_eq!(
            shared.x.to_string(),
            "108127657902349890608713381133328869798433126817450190281707933471728911716600"
        );
        assert_eq!(
            shared.y.to_string(),
            "90081983369721618215244899859661517112066743317494361926578071297084718897517"
        );
        Ok(())
    }

    #[test]
    fn test_pack_public() -> Result<()> {
        let ecdh = Ecdh {
            curve: curve::PRIME256V1.clone(),
            secret: BigInt::from_slice(
                Sign::Plus,
                &[
                    3008988791, 2223512191, 4101290493, 1349918355, 981201553, 1906136310,
                    3328719820, 837222639,
                ],
            ),
            public: EllipticPoint {
                x: BigInt::from_slice(
                    Sign::Plus,
                    &[
                        192391996, 42411882, 3555170359, 1596249776, 1928736291, 3341608003,
                        1479611319, 155190516,
                    ],
                ),
                y: BigInt::from_slice(
                    Sign::Plus,
                    &[
                        3113797789, 2959440885, 2287647648, 3290191409, 693816809, 3512895204,
                        3156405519, 100630943,
                    ],
                ),
            },
        };
        let public = ecdh.pack_public(false)?;
        assert_eq!(
            public.as_slice(),
            &[
                4, 9, 64, 4, 244, 88, 49, 19, 183, 199, 44, 228, 67, 114, 246, 46, 35, 95, 36, 214,
                176, 211, 231, 152, 55, 2, 135, 39, 106, 11, 119, 171, 60, 5, 255, 129, 159, 188,
                34, 237, 15, 209, 98, 134, 228, 41, 90, 205, 233, 196, 28, 86, 49, 136, 90, 187,
                160, 176, 101, 123, 245, 185, 152, 200, 157,
            ]
        );
        Ok(())
    }

    #[test]
    fn test_ecdh_key_exchange() -> Result<()> {
        let curve_p256 = &curve::PRIME256V1.clone();
        let alice = Ecdh::new(curve_p256.clone())?;
        let alice_public_key = alice.pack_public(false)?;
        let bob = Ecdh::new(curve_p256.clone())?;
        let bob_public_key = bob.pack_public(false)?;
        let shared_by_alice = alice.key_exchange(bob_public_key, false)?;
        let shared_by_bob = bob.key_exchange(alice_public_key, false)?;
        assert_eq!(shared_by_alice, shared_by_bob);
        Ok(())
    }
}
