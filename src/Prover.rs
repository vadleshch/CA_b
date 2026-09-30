use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use k256::elliptic_curve::sec1::{ToSec1Point};
use k256::elliptic_curve::Generate;
use rand::Rng;
use k256::elliptic_curve::ops::Reduce;
use sha2::{Digest, Sha256};
use chrono::Local;
use sha2::digest::Update;
use crate::Verifier::FiatShamir;

pub struct Proof
{
    pub R: Vec<ProjectivePoint>,
    pub C: Vec<ProjectivePoint>,
    pub P: Vec<ProjectivePoint>,
    pub H_a: ProjectivePoint,
    pub C_out: ProjectivePoint,
    pub T_out: ProjectivePoint,
    pub T_b: Vec<ProjectivePoint>,
    pub T_r: Vec<ProjectivePoint>,
    pub Tags: Vec<ProjectivePoint>,
    pub U_l: Vec<ProjectivePoint>,
    pub V_l: Vec<ProjectivePoint>,
    pub z_a: Scalar,
    pub z_b: Scalar,
    pub z_r: Scalar,
    pub d_l: Vec<Scalar>,
    pub c_l: Vec<Scalar>,
}

fn GenProof(A_Pk: Vec<ProjectivePoint>, Tags: Vec<ProjectivePoint>, a: Scalar, b: Scalar, r: Scalar, j: usize) -> (Vec<ProjectivePoint>, Vec<ProjectivePoint>, ProjectivePoint, ProjectivePoint)
{
    let G = ProjectivePoint::GENERATOR;
    let mut rng = rand::thread_rng();

    let mut R: Vec<ProjectivePoint> = Vec::new();
    let mut C: Vec<ProjectivePoint> = Vec::new();

    for i in 0..A_Pk.len()
    {
        R.push(A_Pk[i] * r);
        C.push(A_Pk[i] * b);
    }

    let H_a = Tags[j] + r * G;
    let C_out = H_a * a + G * b;
    (R, C, H_a, C_out)
}



fn Commitment(A_Pk: Vec<ProjectivePoint>, Tags: Vec<ProjectivePoint>, a: Scalar, b: Scalar, r: Scalar, j: usize, R: Vec<ProjectivePoint>, C: Vec<ProjectivePoint>, H_a: ProjectivePoint, C_out: ProjectivePoint) -> Proof//(ProjectivePoint, Vec<ProjectivePoint>, Vec<ProjectivePoint>, Vec<ProjectivePoint>, Vec<ProjectivePoint>, Scalar, Scalar, Scalar, Vec<Scalar>, Vec<Scalar>)
{
    let G = ProjectivePoint::GENERATOR;
    let t = Tags.len();
    let n= A_Pk.len();

    let r_a = Scalar::generate();
    let r_b = Scalar::generate();
    let r_r = Scalar::generate();
    let r_t = Scalar::generate();
    let mut c_l: Vec<Scalar> = Vec::new();
    let mut d_l: Vec<Scalar> = Vec::new();

    let mut T_b: Vec<ProjectivePoint> = Vec::new();
    let mut T_r: Vec<ProjectivePoint> = Vec::new();

    let T_out = r_a * H_a + r_b * G;

    for k in 0..n
    {
        T_b.push(r_b * A_Pk[k]);
        T_r.push(r_r * A_Pk[k]);
    }

    let mut U_l: Vec<ProjectivePoint> = Vec::new();
    let mut V_l: Vec<ProjectivePoint> = Vec::new();

    for i in 0..t
    {
        c_l.push(Scalar::generate());
        d_l.push(Scalar::generate());
        if(i != j)
        {
            U_l.push(c_l[i] * G - d_l[i] * (H_a - Tags[i]));
            V_l.push(c_l[i] * A_Pk[0] - d_l[i] * R[0]);
        }
        else
        {
            U_l.push(r_t * G);
            V_l.push(r_t * A_Pk[0]);
        }
    }
    let e = FiatShamir(&T_out, &C_out, &H_a, &G, &C, &R, &Tags, &A_Pk, &T_b, &T_r, &U_l, &V_l);

    let z_a = r_a + a * e;
    let z_b = r_b + b * e;
    let z_r = r_r + r * e;
    let mut temp:Scalar = Scalar::ZERO;

    for i in 0..t
    {
        if i != j
        {
            temp = temp + d_l[i];
        }
    }
    d_l[j] = e - temp;
    c_l[j] = r_t + d_l[j] * r;
    Proof {R: R, C: C, P: A_Pk, H_a: H_a, C_out: C_out, T_out: T_out, T_b: T_b, T_r: T_r, U_l: U_l, V_l: V_l, z_a: z_a, z_b: z_b, z_r: z_r, d_l: d_l, c_l: c_l, Tags: Tags}
}