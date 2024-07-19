use mpz_core::LpnEstimator;


fn main(){
    let sec = LpnEstimator::security_for_binary(1 << 10, 652, 57);
    // let sec = LpnEstimator::security_for_binary(1 << 12, 1589, 98);
    // let sec = LpnEstimator::security_for_binary(1 << 14, 3482, 198);
    // let sec = LpnEstimator::security_for_binary(1 << 16, 7391, 389);
    // let sec = LpnEstimator::security_for_binary(1 << 22, 67440, 2735);    
    println!("security: {} bits", sec);
}