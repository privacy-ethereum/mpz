use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct ApiResponse<'a> {
    users: Vec<User<'a>>,
    pagination: Pagination,
    filters: Filters<'a>,
    api_version: &'a str,
    request_id: &'a str,
}

#[derive(Deserialize)]
struct User<'a> {
    id: u32,
    name: &'a str,
    email: &'a str,
    age: u32,
    active: bool,
    roles: Vec<&'a str>,
    address: Address<'a>,
    preferences: Preferences<'a>,
    scores: Vec<u32>,
    metadata: Metadata<'a>,
}

#[derive(Deserialize)]
struct Address<'a> {
    street: &'a str,
    city: &'a str,
    state: &'a str,
    zip: &'a str,
    country: &'a str,
}

#[derive(Deserialize)]
struct Preferences<'a> {
    theme: &'a str,
    language: &'a str,
    notifications: Notifications,
    timezone: &'a str,
}

#[derive(Deserialize)]
struct Notifications {
    email: bool,
    sms: bool,
    push: bool,
}

#[derive(Deserialize)]
struct Pagination {
    page: u32,
    per_page: u32,
    total: u32,
    total_pages: u32,
}

#[derive(Deserialize)]
struct Filters<'a> {
    active_only: bool,
    min_age: Option<u32>,
    max_age: Option<u32>,
    roles: Vec<&'a str>,
    sort_by: &'a str,
    sort_order: &'a str,
}

#[derive(Deserialize)]
struct Metadata<'a> {
    created_at: &'a str,
    updated_at: &'a str,
    login_count: u32,
    last_ip: &'a str,
}

/// Hash `msg_len` bytes starting at `msg_ptr` with SHA-256.
///
/// Writes the 32-byte digest to `out_ptr`. Returns 0.
#[no_mangle]
pub unsafe extern "C" fn sha256(msg_ptr: u32, msg_len: u32, out_ptr: u32) -> u32 {
    let msg = core::slice::from_raw_parts(msg_ptr as *const u8, msg_len as usize);

    let digest = Sha256::digest(msg);

    let out = core::slice::from_raw_parts_mut(out_ptr as *mut u8, 32);
    out.copy_from_slice(&digest);

    0
}

/// Parse `json_len` bytes of JSON starting at `json_ptr` into a
/// typed struct. Returns 0 on success, 1 on parse error.
#[no_mangle]
pub unsafe extern "C" fn json_parse(json_ptr: u32, json_len: u32) -> u32 {
    let json = core::slice::from_raw_parts(json_ptr as *const u8, json_len as usize);

    let response = serde_json::from_slice::<ApiResponse>(json).unwrap();
    assert!(!response.users.is_empty());

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parse_fixture() {
        let json = include_bytes!("../fixtures/sample.json");
        parse_json(json);
    }
}
