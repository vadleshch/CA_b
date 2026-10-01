mod Prover;
mod Verifier;

use k256::{ProjectivePoint, Scalar};
use k256::elliptic_curve::Generate;
use rand::Rng;
use std::hint::black_box;
use std::time::Instant;
use peakmem_alloc::{PeakMemAlloc, PeakMemAllocTrait};

#[global_allocator]
static ALLOC: PeakMemAlloc<std::alloc::System> = PeakMemAlloc::system();

fn main()
{
    let N: Vec<usize> = vec![5, 10, 20];
    let T: Vec<usize> = vec![5, 10, 20];
    let M: Vec<usize> = vec![1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

    let repeats = 30;
    let ctx = b"CA/benchmark/v1";

    println!("{:<12} {:>6} {:>6} {:>8} {:>20} {:>24}", "Operation", "n", "t", "m", "Average time (ms)", "Average peak (MB)");

    for i in 0..N.len()
    {
        for j in 0..T.len()
        {
            Benchmark("prove", N[i], T[j], 1, repeats, ctx);
        }
    }

    let n = 10;
    let t = 5;

    for i in 0..M.len()
    {
        Benchmark("verify", n, t, M[i], repeats, ctx);
    }
}

fn Benchmark(operation: &str, n: usize, t: usize, m: usize, repeats: usize, ctx: &[u8])
{
    assert!(n > 0 && t > 0 && m > 0 && repeats > 0);
    assert!(operation == "prove" || operation == "verify");

    let G = ProjectivePoint::GENERATOR;
    let mut rng = rand::thread_rng();

    let mut A_Pk: Vec<ProjectivePoint> = Vec::new();
    let mut Tags: Vec<ProjectivePoint> = Vec::new();
    let mut p: Vec<Prover::Proof> = Vec::new();

    for _ in 0..n
    {
        let mut sk = Scalar::generate();

        while sk == Scalar::ZERO
        {
            sk = Scalar::generate();
        }

        A_Pk.push(sk.invert().unwrap() * G);
    }

    for _ in 0..t
    {
        Tags.push(Scalar::generate() * G);
    }

    if operation == "verify"
    {
        for _ in 0..m
        {
            let a = Scalar::from(rng.gen_range(0..i32::MAX) as u64);
            let b = Scalar::generate();
            let r = Scalar::generate();
            let j = rng.gen_range(0..t);

            let (R, C, H_a, C_out) = Prover::GenProof(A_Pk.clone(), Tags.clone(), a, b, r, j);

            p.push(Prover::Commitment(A_Pk.clone(), Tags.clone(), a, b, r, j, R, C, H_a, C_out, ctx));
        }
    }

    let point_size = std::mem::size_of::<ProjectivePoint>();
    let scalar_size = std::mem::size_of::<Scalar>();

    let mut input = (A_Pk.capacity() + Tags.capacity()) * point_size;
    input += p.capacity() * std::mem::size_of::<Prover::Proof>();

    for i in 0..p.len()
    {
        input += (p[i].R.capacity() + p[i].C.capacity() + p[i].P.capacity() + p[i].T_b.capacity() + p[i].T_r.capacity() + p[i].Tags.capacity() + p[i].U_l.capacity() + p[i].V_l.capacity()) * point_size;
        input += (p[i].d_l.capacity() + p[i].c_l.capacity()) * scalar_size;
    }

    let mut average_time = 0.0;
    let mut average_memory = 0.0;

    for i in 0..repeats + 2
    {
        let time;
        let memory;

        if operation == "prove"
        {
            let a = Scalar::from(rng.gen_range(0..i32::MAX) as u64);
            let b = Scalar::generate();
            let r = Scalar::generate();
            let j = rng.gen_range(0..t);

            ALLOC.reset_peak_memory();
            let start = Instant::now();

            let (R, C, H_a, C_out) = Prover::GenProof(A_Pk.clone(), Tags.clone(), a, b, r, j);
            let proof = Prover::Commitment(A_Pk.clone(), Tags.clone(), a, b, r, j, R, C, H_a, C_out, ctx);

            black_box(&proof);

            time = start.elapsed().as_secs_f64() * 1000.0;
            memory = ALLOC.get_peak_memory();

            drop(proof);
        }
        else
        {
            ALLOC.reset_peak_memory();
            let start = Instant::now();

            let result = Verifier::Verify(&p, &Tags, &A_Pk, ctx);

            time = start.elapsed().as_secs_f64() * 1000.0;
            memory = ALLOC.get_peak_memory();

            assert!(result);
        }

        if i >= 2
        {
            average_time += time;
            average_memory += (input + memory) as f64;
        }
    }

    average_time = average_time / repeats as f64;
    average_memory = average_memory / repeats as f64 / 1048576.0;

    println!("{:<12} {:>6} {:>6} {:>8} {:>20.0} {:>24.3}", operation, n, t, m, average_time, average_memory);
}