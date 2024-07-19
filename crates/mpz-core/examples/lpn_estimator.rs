use mpz_core::LpnEstimator;


fn main(){
    let sec = LpnEstimator::security_for_binary_regular(1<<10, 652, 57);
    println!("security: {} bits", sec);
}