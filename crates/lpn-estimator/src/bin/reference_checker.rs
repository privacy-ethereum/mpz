use lpn_estimator::{LpnParams, LpnType};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator};
use std::{path::Path, process::Command};

const ESTIMATOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lpnestimator.com/estimator.py");
const EXPECTED_TABLE_FORMAT: &str = "t, n, s";

fn main() {
    let mut args = std::env::args().skip(1);

    if args.len() != 3 {
        panic!("You need to provide 3 parameters for the LPN reference checker.")
    }

    let typ = match args.next().unwrap().as_str() {
        "exact" => LpnType::Exact,
        "regular" => LpnType::Regular,
        _ => panic!("Unable to parse LPN type"),
    };

    let k: u64 = args.next().unwrap().parse().expect("unable to parse k");

    let path = args.next().unwrap();
    let path = Path::new(&path);
    let table = std::fs::read_to_string(path).expect("unable to open table");

    let lpns = create_lpns(table, typ, k);
    let mut lpns_reference = Vec::with_capacity(lpns.len());

    for lpn in lpns.iter() {
        let lpn_ref = compute_security_with_reference(lpn);
        println!(
            "security: original {}, reference {}",
            lpn.security(),
            lpn_ref.security()
        );
        lpns_reference.push(lpn_ref);
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
            .parse::<u64>()
            .expect("unable to parse t");

        let n = values
            .next()
            .expect("unable to read n")
            .parse::<u64>()
            .expect("unable to parse n");

        let s = values
            .next()
            .expect("unable to read s")
            .parse::<u64>()
            .expect("unable to parse s");

        let lpn = LpnParams::new_with_security(typ, n, k, t, s as f64);
        lpns.push(lpn);
    }
    lpns
}

fn compute_security_with_reference(lpn: &LpnParams) -> LpnParams {
    let typ = match lpn.typ() {
        LpnType::Exact => "exact",
        LpnType::Regular => "regular",
    }
    .to_owned();

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
    let security = std::str::from_utf8(&security).expect("unable to read python output");
    let security: f64 = security.parse().expect("unable to parse security to f64");

    LpnParams::new_with_security(lpn.typ(), n, k, t, security)
}
