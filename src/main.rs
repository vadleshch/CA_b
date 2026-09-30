mod Prover;
mod Verifier;

use chrono::Local;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use k256::elliptic_curve::bigint::Reduce;
use k256::elliptic_curve::Generate;
use k256::elliptic_curve::sec1::ToSec1Point;
use rand::Rng;
use sha2::{Digest, Sha256};

fn main() {
    let t = 5;
    let n = 10;
    let m = 32;

    let mut rng = rand::thread_rng();
    let G = ProjectivePoint::GENERATOR;
    let mut A_Pk: Vec<ProjectivePoint> = Vec::new();
    let mut A_Sk: Vec<Scalar> = Vec::new();

    for i in 0..n
    {
        let sk = Scalar::generate();
        A_Sk.push(sk.clone());
        A_Pk.push(sk * G);
    }

    let mut Tags: Vec<ProjectivePoint> = Vec::new();

    for i in 0..t
    {
        let sk: Scalar = Scalar::generate();
        Tags.push(sk * G);
    }

    let mut a: Vec<Scalar> = Vec::new();
    let mut b: Vec<Scalar> = Vec::new();
    let mut r: Vec<Scalar> = Vec::new();
    let mut j: Vec<usize> = Vec::new();

    for i in 0..m
    {
        a.push(Scalar::from(rng.gen_range(0..i32::MAX) as u64));
        b.push(Scalar::generate());
        r.push(Scalar::generate());
        j.push(rng.gen_range(0..Tags.len()));
    }
    
}