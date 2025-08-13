use lpn_estimator::{LpnParams, LpnType};
use mpz_core::lpn::LpnParameters;
use mpz_ot_core::ferret::{REGULAR_PARAMS, UNIFORM_PARAMS};
use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

const REFERENCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lpnestimator.com/estimator.py");

fn main() {
    println!(
        "\nThis program checks the bit security of our LPN instances in `ot-core/src/ferret/config` \
        against a reference implementation."
    );
    println!();

    check(UNIFORM_PARAMS.to_vec(), LpnType::Exact);
    println!();
    check(REGULAR_PARAMS.to_vec(), LpnType::Regular);
}

// Checks the lpn securities in parallel.
fn check(lpns: Vec<LpnParameters>, typ: LpnType) {
    let ref_securities: Arc<Mutex<Vec<Option<f64>>>> = Arc::new(Mutex::new(vec![None; lpns.len()]));

    for (i, &lpn) in lpns.iter().enumerate() {
        let ref_securities = ref_securities.clone();

        rayon::spawn(move || {
            let lpn = LpnParams::new(typ, lpn.n as u64, lpn.k as u64, lpn.t as u64);

            let security = lpn.security();
            let ref_security = compute_ref_security(&lpn);

            let (n, k, t) = lpn.nkt();
            println!(
                "Checked {typ:?} LPN (n={}, k={}, t= {}): \tcomputed security: {:.2}, reference security: {:.2}",
                n, k, t, security, ref_security
            );

            let mut ref_securities = ref_securities.lock().unwrap();
            ref_securities[i] = Some(ref_security);
        });
    }

    loop {
        {
            let lpns = ref_securities.lock().unwrap();
            if lpns.iter().all(|lpn| lpn.is_some()) {
                break;
            }
        }

        std::thread::sleep(Duration::from_secs(2));
    }
}

// Computes the bit security using a reference implementation
fn compute_ref_security(lpn: &LpnParams) -> f64 {
    let typ = match lpn.typ() {
        LpnType::Exact => "exact",
        LpnType::Regular => "regular",
    };

    let (n, k, t) = lpn.nkt();

    let security = Command::new("python")
        .arg(REFERENCE)
        .arg(format!("N={n}"))
        .arg(format!("k={k}"))
        .arg(format!("t={t}"))
        .arg(typ)
        .output()
        .unwrap()
        .stdout;

    let security = std::str::from_utf8(&security)
        .expect("unable to read python output")
        .trim();
    security.parse().expect("unable to parse security to f64")
}
