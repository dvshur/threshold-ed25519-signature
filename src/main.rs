mod polynom;
mod pow;
mod secret;

use curve25519_dalek::scalar::Scalar;
use polynom::Polynom;
use secret::Secret;
use std::convert::TryInto;

// Secret sharing parameters
// Parties number
const N: usize = 5;
// Threshold
const T: usize = 3;

fn main() {
    // secret to share
    let secret_string = "Hello, world!";

    // Parties indexes
    let xs: [Scalar; N] = [
        Scalar::from(1u8),
        Scalar::from(2u8),
        Scalar::from(3u8),
        Scalar::from(4u8),
        Scalar::from(5u8),
    ];

    let secret = Scalar::from_bytes_mod_order(to_canonical_bytes(secret_string).unwrap());

    // SHARE
    let shares = shamir_share(&xs, &secret);

    // RESHARE
    // 1. calculate sij
    // i — sender from group 0..T
    // j — recipient from group -0..N'
    // for now consider simple case:
    // T' = T and N' = N
    let senders: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let senders_shares: &[Scalar; T] = &shares[0..T].try_into().expect("fatal error");

    let mut ss = [[Scalar::zero(); N]; T];
    for i in 0..T {
        // each sender chares his secret with Shamir SS
        // and sends them to all recipients
        ss[i] = shamir_share(&xs, &senders_shares[i]);
    }

    // 2. reconstruct each party from shares sent to it
    let shares_v2 = [
        shamir_reconstruct(&senders, &[ss[0][0], ss[1][0], ss[2][0]]),
        shamir_reconstruct(&senders, &[ss[0][1], ss[1][1], ss[2][1]]),
        shamir_reconstruct(&senders, &[ss[0][2], ss[1][2], ss[2][2]]),
        shamir_reconstruct(&senders, &[ss[0][3], ss[1][3], ss[2][3]]),
        shamir_reconstruct(&senders, &[ss[0][4], ss[1][4], ss[2][4]]),
    ];

    // RECONSTRUCT
    let reconstruct_participants: &[Scalar; T] = &xs[0..T].try_into().expect("fatal error");
    let reconstruct_participants_shares: &[Scalar; T] =
        &shares_v2[0..T].try_into().expect("fatal error");

    // check that shares are not equal
    for i in 0..N {
        assert!(shares[i] != shares_v2[i]);
    }

    let secret_reconstructed =
        shamir_reconstruct(reconstruct_participants, reconstruct_participants_shares);

    let secret_reconstructed_string =
        from_canonical_bytes(secret_reconstructed.as_bytes()).unwrap();

    println!("{}", secret_reconstructed_string);
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

fn shamir_reconstruct(xs: &[Scalar; T], shares: &[Scalar; T]) -> Scalar {
    let lagrange_coeffs = lagrange_coeffs_at_zero(xs);

    let mut res = Scalar::zero();
    for i in 0..T {
        res += lagrange_coeffs[i] * shares[i];
    }

    res
}
