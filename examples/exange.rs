use simple_ecdh::curve::PRIME256V1;
use simple_ecdh::{Ecdh, EcdhError, EllipticCurve, EllipticPoint, KeyExchange};

fn main() -> Result<(), EcdhError> {
    let curve_p256 = &PRIME256V1.clone();

    let alice = Ecdh::new(curve_p256.clone())?;
    let alice_public_key = alice.pack_public(false)?;

    let bob = Ecdh::new(curve_p256.clone())?;
    let bob_public_key = bob.pack_public(false)?;

    let shared_alice = alice.key_exchange(bob_public_key, false)?;

    let shared_bob = bob.key_exchange(alice_public_key, false)?;

    println!("shared_alice: {:?}", shared_alice);
    println!("shared_bob: {:?}", shared_bob);

    Ok(())
}
