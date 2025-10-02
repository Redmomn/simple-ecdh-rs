pub mod curve;
mod ecdh;

pub use ecdh::{Ecdh, EcdhError, EllipticCurve};

pub trait KeyExchange {
    type Error;

    fn key_exchange<T: AsRef<[u8]>>(&self, public: T, hash: bool) -> Result<Vec<u8>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_k192() -> Result<(), EcdhError> {
        let curve_k192 = curve::SECP192K1;
        let alice = Ecdh::new(curve_k192.clone())?;
        let alice_public_key = alice.pack_public(false)?;
        let bob = Ecdh::new(curve_k192.clone())?;
        let bob_public_key = bob.pack_public(false)?;
        let shared_by_alice = alice.key_exchange(bob_public_key, false)?;
        let shared_by_bob = bob.key_exchange(alice_public_key, false)?;
        assert_eq!(shared_by_alice, shared_by_bob);
        Ok(())
    }

    #[test]
    fn test_ecdh_p256() -> Result<(), EcdhError> {
        let curve_p256 = curve::PRIME256V1;
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
