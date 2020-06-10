mod polynom;
mod pow;

use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
// use curve25519_dalek::
// use digest::Digest;
use digest::{Digest, Reset};
use ed25519_dalek::{ExpandedSecretKey, Keypair, PublicKey, SecretKey, Sha512, Signature};
use polynom::Polynom;
use std::convert::TryInto;

// Secret sharing parameters
// Parties number
const N: usize = 5;
// Threshold
const T: usize = 1;

#[allow(non_snake_case)]
fn main() {
    // key pair to split
    let mut csprng = rand::thread_rng();

    let rnd_scalar = Scalar::random(&mut csprng);
    let secret_key = SecretKey::from_bytes(rnd_scalar.as_bytes()).unwrap();
    let public_key = PublicKey::from(&secret_key);
    let key_pair = Keypair {
        secret: secret_key,
        public: public_key,
    };

    // Parties indexes
    let xs: [Scalar; N] = [
        Scalar::from(1u8),
        Scalar::from(2u8),
        Scalar::from(3u8),
        Scalar::from(4u8),
        Scalar::from(5u8),
    ];

    let secret = Scalar::from_bytes_mod_order(key_pair.secret.to_bytes());

    assert!(secret.as_bytes() == key_pair.secret.as_bytes());

    // KEY SHARES
    let shares = shamir_share(&xs, &secret);

    for share in &shares {
        assert!(*share == secret);
        assert!(share.as_bytes() == key_pair.secret.as_bytes());
    }

    // SIGN
    let message: &[u8] = b"Hello, world";

    // T signers, [0..T]
    let signers: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let signers_shares: &[Scalar; T] = &shares[0..T].try_into().expect("fatal error");

    assert!(signers.len() == 1);

    // make expanded secret keys out of shares
    let exp_secret_keys: [(Scalar, [u8; 32]); T] = {
        let mut res = [(Scalar::zero(), [0u8; 32]); T];
        for i in 0..T {
            // todo should I make it out of share, or apply lagrange coeff first?
            res[i] = expanded_secret_key(&signers_shares[i].as_bytes());
        }
        res
    };

    assert!(exp_secret_keys.len() == 1);
    assert!(exp_secret_keys[0].0 != shares[0]);

    // generate ri
    let rs: [Scalar; T] = {
        let mut res = [Scalar::zero(); T];
        for i in 0..T {
            let mut h = Sha512::new();

            h.input(&exp_secret_keys[i].1);
            h.input(&message);

            res[i] = Scalar::from_hash(h.clone());
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

    assert!(Rs[0].compress() == R);

    // calculate k
    let k = {
        let mut h = Sha512::new();
        h.input(R.as_bytes());
        h.input(key_pair.public.as_bytes());
        h.input(&message);
        Scalar::from_hash(h)
    };

    // lagrange coefficients
    let lagrange_coeffs = lagrange_coeffs_at_zero(signers);

    assert!(lagrange_coeffs[0] == Scalar::one());

    let ss: [Scalar; T] = {
        let mut res = [Scalar::zero(); T];
        for i in 0..T {
            res[i] = &(&k * &exp_secret_keys[i].0) + &rs[i]; // * &lagrange_coeffs[i];
        }
        res
    };

    let s: Scalar = ss.iter().sum();

    // println!("r: {:?}, R: {:?}, k: {:?}, s: {:?}", rs[0], Rs[0], k, ss[0]);

    assert!(s == ss[0]);

    let sig_bytes = [R.to_bytes(), s.to_bytes()].concat();

    let signature = Signature::from_bytes(&sig_bytes).unwrap();

    // sign using staightforward way
    // let signature2 = ExpandedSecretKey::from(&key_pair.secret).sign(message, &key_pair.public);

    // VERIFY
    match key_pair.public.verify(message, &signature) {
        Ok(_) => println!("Sig verified, cool"),
        Err(_) => println!("Failed"),
    }

    // println!("{}", secret_reconstructed_string);
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

// fn shamir_reconstruct(xs: &[Scalar; T], shares: &[Scalar; T]) -> Scalar {
//     let lagrange_coeffs = lagrange_coeffs_at_zero(xs);

//     let mut res = Scalar::zero();
//     for i in 0..T {
//         res += lagrange_coeffs[i] * shares[i];
//     }

//     res
// }

fn expanded_secret_key(secret_key: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let mut h: Sha512 = Sha512::default();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    h.input(secret_key);
    hash.copy_from_slice(h.result().as_slice());

    lower.copy_from_slice(&hash[00..32]);
    upper.copy_from_slice(&hash[32..64]);

    lower[0] &= 248;
    lower[31] &= 63;
    lower[31] |= 64;

    (Scalar::from_bits(lower), upper)
}
