use lpn_estimator::LpnEstimator;

fn main() {
    eprintln!("\nThis program estimates the bit security for exact, primal LPN over F2 considering well-known attacks.");
    eprintln!("Parameters N, k, t");
    eprintln!("\tN - number of samples");
    eprintln!("\tk - length of secret");
    eprintln!("\tt - hamming weight of noise\n");

    let args = std::env::args().skip(1);
    if args.len() != 3 {
        panic!("You need to provide 3 parameters for the LPN estimator.")
    }

    let args: Vec<u64> = args
        .map(|arg| arg.parse().expect("Unable to parse number"))
        .collect();

    let n = args[0];
    let k = args[1];
    let t = args[2];

    let security = LpnEstimator::security_for_binary(n, k, t);

    println!("{security:.2}");
}
