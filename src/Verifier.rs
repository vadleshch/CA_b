use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::{Generate, Group};
use crate::Prover::Proof;

fn Verify(p: Vec<Proof>) -> bool
{
    let m = p.len();
    let t = p[0].U_l.len();
    let n = p[0].P.len();
    let G = ProjectivePoint::GENERATOR;
    let mut temp = Scalar::ZERO;

    let mut S_out: Vec<ProjectivePoint> = Vec::new();
    let mut S_u: Vec<ProjectivePoint> = Vec::new();
    let mut S_v: Vec<ProjectivePoint> = Vec::new();
    let mut S_b: Vec<ProjectivePoint> = Vec::new();
    let mut S_r: Vec<ProjectivePoint> = Vec::new();

    let mut s_out: Vec<Scalar> = Vec::new();
    let mut s_u: Vec<Scalar> = Vec::new();
    let mut s_r: Vec<Scalar> = Vec::new();
    let mut s_b: Vec<Scalar> = Vec::new();
    let mut s_r: Vec<Scalar> = Vec::new();

    let mut delta: Vec<Scalar> = Vec::new();
    let mut gamma: Vec<Scalar> = Vec::new();
    let mut zetta: Vec<Scalar> = Vec::new();

    for i in 0..m
    {
        delta.push(GenScal());
        gamma.push(GenScal());
    }
    for i in 0..t
    {
        zetta.push(GenScal());
    }

    //S_out

    for i in 0..m
    {
        S_out.push(p[i].H_a);
        s_out.push(delta[i] * p[i].z_a);
        S_out.push(p[i].T_out);
        s_out.push(delta[i]);
        S_out.push(p[i].C_out);
        s_out.push(delta[i]); //e_i!

        for l in 0..t
        {

        }
    }

    S_out.push(G);

    for i in 0..m
    {
        temp = temp + delta[i] * p[i].z_b;
    }

    s_out.push(temp);


    true
}

fn MulVec (A: Vec<Scalar>, B: Vec<Scalar>) -> Vec<Scalar>
{
    let n = A.len();
    let mut C: Vec<Scalar> = Vec::new();
    for i in 0..n
    {
        C[i] = A[i] * B[i];
    }
    return C;
}

fn GetSum (A: Vec<Scalar>) -> Scalar
{
    let n = A.len();
    let mut temp = Scalar::ZERO;
    for i in 0..n
    {
        temp += A[i];
    }
    return temp;
}

fn GenScal () -> Scalar
{
    let mut temp = Scalar::generate();
    while temp == Scalar::ZERO
    {
        temp = Scalar::generate();
    }
    return temp;
}