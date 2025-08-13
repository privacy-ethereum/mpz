use lpn_estimator::{LpnParams, LpnType};
use mpz_ot_core::ferret::{REGULAR_PARAMS, UNIFORM_PARAMS};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

const ESTIMATOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lpnestimator.com/estimator.py");
const MAX_SECS_WITHOUT_PROGRESS: u32 = 180;

fn main() {
    eprintln!(
        "\nThis program checks the bit security of our LPN instances in ot-core/src/ferret/config
        against a reference implementation."
    );

    let reference_lpns: Arc<Mutex<Vec<Option<LpnParams>>>> =
        Arc::new(Mutex::new(vec![None; lpns.len()]));

    for (k, &lpn) in lpns.iter().enumerate() {
        let reference_lpns = reference_lpns.clone();

        rayon::spawn(move || {
            let ref_lpn = compute_security_with_reference_impl(lpn);
            let mut reference_lpns = reference_lpns.lock().unwrap();
            reference_lpns[k] = Some(ref_lpn);
            eprintln!("Finished checking one table entry...");
        });
    }

    let mut count_finished = 0;
    let mut seconds_elapsed_since_progress = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        seconds_elapsed_since_progress += 1;

        if let Ok(reference_lpns) = reference_lpns.lock() {
            // Put some maximum time on computation
            let new_finished =
                reference_lpns.iter().filter(|lpn| lpn.is_some()).count() - count_finished;
            count_finished += new_finished;

            if new_finished > 0 {
                seconds_elapsed_since_progress = 0;
            } else if new_finished == 0
                && seconds_elapsed_since_progress >= MAX_SECS_WITHOUT_PROGRESS
            {
                eprintln!("Could not compute all instances! Computation taking too long.");
                break;
            }

            // All finished
            if reference_lpns.iter().all(|lpn| lpn.is_some()) {
                break;
            }
        }
    }

    let reference_lpns = reference_lpns
        .lock()
        .unwrap()
        .iter()
        .filter(|lpn| lpn.is_some())
        .copied()
        .collect::<Option<Vec<_>>>()
        .unwrap();

    println!("\nShowing computed and reference bit securities:");
    for (expected, reference) in lpns.iter().zip(reference_lpns.iter()) {
        println!(
            "{expected:?}, computed: {}, reference: {}",
            expected.security() as u64,
            reference.security() as u64
        );
    }
}

fn compute_security_with_reference_impl(lpn: LpnParams) -> LpnParams {
    let typ = match lpn.typ() {
        LpnType::Exact => "exact",
        LpnType::Regular => "regular",
    };

    let (n, k, t) = lpn.nkt();

    let security = Command::new("python")
        .arg(ESTIMATOR)
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
    let security: f64 = security.parse().expect("unable to parse security to f64");

    unsafe { LpnParams::new_with_security(lpn.typ(), n, k, t, security) }
}
