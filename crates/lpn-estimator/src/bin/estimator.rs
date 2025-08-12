use lpn_estimator::{LpnParams, LpnType};
use quote::quote;

fn main() {
    eprintln!(
        "\nThis program searches primal LPN instances over F2 satisfying a minimum bit security for a given secret length."
    );
    eprintln!(
        "Output is a rust module file lpn_parms.rs, which can be included in other projects."
    );
    eprintln!("\nParameters: type, s, k, max_n (optional)");
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

    // Safety check
    for lpn in lpns {
        assert!(lpn.security() >= s, "Computed security is below threshold.");
        assert!(
            lpn.nkt().1 >= k,
            "Computed secret length is below threshold."
        );
    }

    let table = quote! {
        //! This module is automatically generated with the crate `lpn-estimator` using the binary `estimator.rs`.
        //! Do not edit manually!
        //!
        //! If you want to make changes run the estimator and replace this file with the genrated output.

        use mpz_core::lpn::LpnParameters;

        static LPN_PARAMS: &[LpnParameters] = [#(#lpns),*];

    };
    let generated_code = table.to_string();

    println!("{}", generated_code);
}
