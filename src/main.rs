mod polynom;
mod pow;

use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use digest::Digest;
use ed25519_dalek::{PublicKey, SecretKey, Sha512, Signature};
use polynom::Polynom;
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

// Secret sharing parameters
// Parties number
const N: usize = 5;
// Threshold
const T: usize = 3;

const PREFIX: [u8; 32] = [255u8; 32];

#[allow(non_snake_case)]
fn main() {
    // Parties indexes
    let xs: [Scalar; N] = [
        Scalar::from(1u8),
        Scalar::from(2u8),
        Scalar::from(3u8),
        Scalar::from(4u8),
        Scalar::from(5u8),
    ];

    let mut csprng = rand::thread_rng();
    let (sk, pk) = generate_key_pair(&mut csprng);

    // KEY SHARES
    let shares = shamir_share(&xs, &sk);

    // SIGN
    let message: &[u8] = b"Hello, world";

    // T signers, [0..T]
    let signers: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let signers_shares: &[Scalar; T] = &shares[0..T].try_into().expect("fatal error");

    // lagrange coefficients
    let lagrange_coeffs = lagrange_coeffs_at_zero(signers);

    // generate ri
    let rs: [Scalar; T] = {
        let mut res = [Scalar::zero(); T];
        for i in 0..T {
            let random = {
                let mut r = [0u8; 64];
                csprng.fill_bytes(&mut r);
                r
            };

            let mut h = Sha512::new();

            h.input(&PREFIX);
            h.input(signers_shares[i].as_bytes());
            h.input(&message);
            h.input(&random[0..64]);

            res[i] = Scalar::from_hash(h);
        }
        res
    };

    // calculate Ri
    let Rs: [EdwardsPoint; T] = {
        let mut res = [EdwardsPoint::default(); T];
        for i in 0..T {
            res[i] = &rs[i] * &constants::ED25519_BASEPOINT_TABLE;
        }
        res
    };

    // sum Ri to get R
    let R: CompressedEdwardsY = {
        let R: EdwardsPoint = Rs.iter().sum();
        R.compress()
    };

    // calculate k
    let k = {
        let mut h = Sha512::new();
        h.input(R.as_bytes());
        h.input(pk.as_bytes());
        h.input(&message);
        Scalar::from_hash(h)
    };

    let ss: [Scalar; T] = {
        let mut res = [Scalar::zero(); T];
        for i in 0..T {
            res[i] = &(&shares[i] * &lagrange_coeffs[i] * &k) + &rs[i];
        }
        res
    };

    let s: Scalar = ss.iter().sum();

    let sig_bytes = [R.to_bytes(), s.to_bytes()].concat();

    let signature = Signature::from_bytes(&sig_bytes).unwrap();

    // VERIFY
    match pk.verify(message, &signature) {
        Ok(_) => println!("Sig verified, cool"),
        Err(_) => println!("Failed"),
    }
}

fn lagrange_coeffs_at_zero(xs: &[Scalar; T]) -> [Scalar; T] {
    let mut cs = [Scalar::one(); T];

    for i in 0..T {
        for j in 0..T {
            if i != j {
                cs[i] *= xs[j] * (xs[j] - xs[i]).invert();
            }
        }
    }

    cs
}

fn shamir_share(xs: &[Scalar; N], secret: &Scalar) -> [Scalar; N] {
    let mut rng = rand::thread_rng();

    // create a random polynom f(x) or order T - 1 with the secret as a zero coefficient
    let polynom = Polynom::random(&mut rng, &secret, T - 1);

    // create shares for parties as yi = f(xi);
    let mut res = [Scalar::zero(); N];
    for (i, x) in xs.iter().enumerate() {
        res[i] = polynom.at(x);
    }

    res
}

fn generate_key_pair<T>(mut csprng: &mut T) -> (Scalar, PublicKey)
where
    T: CryptoRng + RngCore,
{
    let seed = SecretKey::generate(&mut csprng);

    let pk = PublicKey::from(&seed);

    let mut digest: [u8; 32] = Sha512::digest(seed.as_bytes())[00..32].try_into().unwrap();
    // do a conversion as per RFC
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;

    (Scalar::from_bits(digest), pk)
}
