use reqwest::blocking as requests;

const PROTOCOL_0_0_2: &'static str = include_str!("../../protocols/v0.0.2.json");

pub fn get_pinned_protocol(version: &str) -> String {
    match version {
        "0.0.2" => PROTOCOL_0_0_2.to_string(),
        _ => panic!("Protocol version not found."),
    }
}

pub fn get_online_protocol(version: &str) -> String {
    let protocol_host = "https://cdn.jsdelivr.net/gh/blyssprivacy/verifier/protocols/";

    let protocol_url = protocol_host.to_string() + "v" + version + ".json";
    let response = requests::get(&protocol_url).expect("Failed to fetch protocol document");
    if !response.status().is_success() {
        panic!("Failed to fetch protocol document at {}", protocol_url);
    }
    let protocol_document = response.text().expect("Failed to read response text");
    protocol_document
}
