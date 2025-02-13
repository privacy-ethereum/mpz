use lpn_estimator::{LpnParams, LpnType};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

const ESTIMATOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lpnestimator.com/estimator.py");
const EXPECTED_TABLE_FORMAT: &str = "t, n, s";

fn main() {
    eprintln!(
        "\nThis program checks the bit security of LPN tables against a reference implementation."
    );
    eprintln!("Parameters: path, type, k");
    eprintln!("\tpath - the path to the LPN table");
    eprintln!("\ttype - either \"regular\" or \"exact\"");
    eprintln!("\tk - length of secret\n");

    let mut args = std::env::args().skip(1);

    if args.len() != 3 {
        panic!("You need to provide 3 parameters.")
    }

    let path = args.next().unwrap();
    let path = Path::new(&path);
    let table = std::fs::read_to_string(path).expect("unable to open table");

    let typ = match args.next().unwrap().as_str() {
        "exact" => LpnType::Exact,
        "regular" => LpnType::Regular,
        _ => panic!("Unable to parse LPN type"),
    };

    let k: u64 = args.next().unwrap().parse().expect("unable to parse k");

    let lpns = create_lpns(table, typ, k);
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

    loop {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(reference_lpns) = reference_lpns.lock() {
            if reference_lpns.iter().all(|lpn| lpn.is_some()) {
                break;
            }
        }
    }

    let reference_lpns = reference_lpns
        .lock()
        .unwrap()
        .iter()
        .copied()
        .collect::<Option<Vec<_>>>()
        .unwrap();

    println!("\nShowing computed and reference bit securities:");
    for (expected, reference) in lpns.iter().zip(reference_lpns.iter()) {
        println!(
            "{expected:?}, computed: {}, reference: {}",
            expected.security(),
            reference.security()
        );
    }
}

fn create_lpns(table: String, typ: LpnType, k: u64) -> Vec<LpnParams> {
    let mut table = table.lines();
    let header = table.next().expect("unable to read table header");

    assert_eq!(
        header, EXPECTED_TABLE_FORMAT,
        "Expected a csv table for lpn parameters in the format ({})",
        EXPECTED_TABLE_FORMAT
    );

    let mut lpns: Vec<LpnParams> = Vec::new();

    for entry in table {
        let mut values = entry.split(',');

        let t = values
            .next()
            .expect("unable to read t")
            .trim()
            .parse::<u64>()
            .expect("unable to parse t");

        let n = values
            .next()
            .expect("unable to read n")
            .trim()
            .parse::<u64>()
            .expect("unable to parse n");

        let s = values
            .next()
            .expect("unable to read s")
            .trim()
            .parse::<u64>()
            .expect("unable to parse s");

        let lpn = LpnParams::new_with_security(typ, n, k, t, s as f64);
        lpns.push(lpn);
    }

    lpns
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

    LpnParams::new_with_security(lpn.typ(), n, k, t, security)
}
