use k256::{FieldBytes, ProjectivePoint, Scalar};
use k256::elliptic_curve::{Generate, Group};
use crate::Prover::Proof;
use chrono::Local;
use k256::elliptic_curve::bigint::Reduce;
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

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
    let mut s_v: Vec<Scalar> = Vec::new();
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
        let e = FiatShamir(&p[i].T_out, &p[i].C_out, &p[i].H_a, &G, &p[i].C, &p[i].R, &p[i].Tags, &p[i].P, &p[i].T_b, &p[i].T_r, &p[i].U_l, &p[i].V_l);

        let mut Se: Scalar = Scalar::ZERO;
        for l in 0..t
        {
            Se = Se + p[i].d_l[l];
        }
        if Se != e
        {
            return false;
        }

        S_out.push(p[i].H_a);
        s_out.push(delta[i] * p[i].z_a);
        S_out.push(-p[i].T_out);
        s_out.push(delta[i]);
        S_out.push(-p[i].C_out);
        s_out.push(delta[i] * e);

        for l in 0..t
        {
            S_u.push(p[i].U_l[l]);
            s_u.push(delta[i] * zetta[l]);
            S_u.push(p[i].H_a - p[i].Tags[l]);
            s_u.push(delta[i] * zetta[l] * p[i].d_l[l]);

            S_v.push(p[i].V_l[l]);
            s_v.push(delta[i] * zetta[l]);
        }

        S_v.push(p[i].R[0]);
        s_v.push(GetSum(MulVec(&p[i].d_l, &zetta)));

        for k in 0..n
        {
            S_b.push(p[i].T_b[k]);
            s_b.push(delta[i] * gamma[k]);
            S_b.push(p[i].C[k]);
            s_b.push(delta[i] * gamma[k] * e);

            S_r.push(p[i].T_r[k]);
            s_r.push(delta[i] * gamma[k]);
            S_r.push(p[i].R[k]);
            s_r.push(delta[i] * gamma[k] * e);
        }
    }

    for k in 0..n
    {
        S_b.push(p[0].P[k]);

        temp = Scalar::ZERO;
        for i in 0..m
        {
            temp = temp + delta[i] * p[i].z_b;
        }
        s_b.push(gamma[k] * temp);

        S_r.push(p[0].P[k]);
        temp = Scalar::ZERO;
        for i in 0..m
        {
            temp = temp + delta[i] * p[i].z_r;
        }
        s_r.push(gamma[k] * temp);
    }
    S_out.push(G);
    S_u.push(-G);
    S_v.push(-p[0].P[0]);

    temp = Scalar::ZERO;
    for i in 0..m
    {
        temp = temp + delta[i] * p[i].z_b;
    }
    s_out.push(temp);

    temp = Scalar::ZERO;
    for i in 0..m
    {
        for l in 0..t
        {
            temp = temp + delta[i] * zetta[l] * p[i].c_l[l];
        }
    }
    s_v.push(temp);
    s_u.push(temp);


    true
}

fn MulVec (A: &Vec<Scalar>, B: &Vec<Scalar>) -> Vec<Scalar>
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

pub fn FiatShamir (T_out: &ProjectivePoint, C_out: &ProjectivePoint, H_a: &ProjectivePoint,
               G: &ProjectivePoint, C: &Vec<ProjectivePoint>, R: &Vec<ProjectivePoint>,
               Tags: &Vec<ProjectivePoint>, A_Pk: &Vec<ProjectivePoint>, T_b: &Vec<ProjectivePoint>,
               T_r: &Vec<ProjectivePoint>, U_l: &Vec<ProjectivePoint>, V_l: &Vec<ProjectivePoint>) -> Scalar
{
    let date = Local::now().date_naive();
    let mut hasher = sha2::Sha256::new();
    Digest::update(&mut hasher, date.to_string().as_bytes());
    hash_point(&mut hasher, &T_out);
    hash_point(&mut hasher, &C_out);
    hash_point(&mut hasher, &H_a);
    hash_point(&mut hasher, &G);
    hash_points(&mut hasher, &C);
    hash_points(&mut hasher, &R);
    hash_points(&mut hasher, &Tags);
    hash_points(&mut hasher, &A_Pk);
    hash_points(&mut hasher, &T_b);
    hash_points(&mut hasher, &T_r);
    hash_points(&mut hasher, &U_l);
    hash_points(&mut hasher, &V_l);

    let digest = hasher.finalize();
    let mut eh = FieldBytes::default();
    eh.copy_from_slice(&digest);
    let e: Scalar = <Scalar as Reduce<FieldBytes>>::reduce(&eh);
    fn hash_point(hasher: &mut Sha256, point: &ProjectivePoint) {
        let encoded = point.to_affine().to_sec1_point(true);
        Digest::update(hasher, encoded.as_bytes());
    }
    fn hash_points(hasher: &mut Sha256, points: &[ProjectivePoint]) {
        for point in points {
            hash_point(hasher, point);
        }
    }

    return e;
}