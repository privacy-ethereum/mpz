use lpn_estimator::{LpnParams, LpnType};

fn main() {
    eprintln!("\nThis program searches primal LPN instances over F2 satisfying a minimum bit security for a given secret length.");
    eprintln!("Parameters: type, s, k, max_n (optional)");
    eprintln!("\ttype - either \"exact\" or \"regular\"");
    eprintln!("\ts - minimum bit security");
    eprintln!("\tk - length of secret");
    eprintln!("\tmax_n (optional) - maximum number of samples to search for\n");

    let mut args = std::env::args().skip(1);
    if args.len() > 4 || args.len() < 3 {
        panic!("You need to provide 3 or 4 parameters for the LPN estimator.")
    }

    let typ = match args.next().unwrap().as_str() {
        "exact" => LpnType::Exact,
        "regular" => LpnType::Regular,
        _ => panic!("Unable to parse LPN type"),
    };

    let s: f64 = args
        .next()
        .unwrap()
        .parse()
        .expect("Unable to parse number");

    let k: u64 = args
        .next()
        .unwrap()
        .parse()
        .expect("Unable to parse number");

    let max_n = args
        .next()
        .map(|n| n.parse().expect("Unable to parse number"));

    let lpns = LpnParams::scan(typ, s, k, max_n);

    eprintln!("Computed the following primal LPN instances for:");
    eprintln!("\ttype: {typ:?}");
    eprintln!("\ts: {s}");
    eprintln!("\tk: {k}");

    println!("t, n, s");
    for lpn in lpns {
        let (n, _, t) = lpn.nkt();
        let s = lpn.security() as u64;
        println!("{}, {}, {}", t, n, s);
    }
}
