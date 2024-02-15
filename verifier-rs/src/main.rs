use base64;
// use pem::parse;
use reqwest::blocking as requests;
use ring;
use serde::Deserialize;
use serde_json;
use sev::{certs::snp::Certificate, firmware::guest::AttestationReport};
use shlex;

#[derive(Debug, Deserialize)]
struct AugementedReport {
    #[serde(flatten)]
    report: AttestationReport,
    vcek: String,
}

struct AttestedComponents {
    shim: Option<String>,
    application: Option<String>,
    ui: Option<String>,
}

mod sevtool;

fn parse_commandline(kernel_cli: String) -> AttestedComponents {
    let mut components = AttestedComponents {
        shim: None,
        application: None,
        ui: None,
    };

    let cli_args = shlex::split(&kernel_cli).unwrap();
    for arg in cli_args {
        if arg.starts_with("shim=") {
            components.shim = Some(arg.split('=').collect());
        } else if arg.starts_with("application=") {
            components.application = Some(arg.split('=').collect());
        } else if arg.starts_with("ui=") {
            components.ui = Some(arg.split('=').collect());
        }
    }

    components
}

fn verify(attestation_document: String, protocol_document: String) {
    // A: Verify the attestation document
    // 1. Parse the attestation document
    let attestation_json: serde_json::Value = serde_json::from_str(&attestation_document).unwrap();
    // Split into CPU-signed report and VCEK
    let cpu_attestation_str = attestation_json["cpu_attestation"].clone().to_string();
    let cpu_attestation_and_vcek: AugementedReport =
        serde_json::from_str(&cpu_attestation_str).unwrap();
    let cpu_attestation = cpu_attestation_and_vcek.report;
    // Parse VCEK into a certificate
    let vcek_base64 = cpu_attestation_and_vcek.vcek;
    let vcek_bytes = base64::decode(&format!("{}==", vcek_base64)).unwrap();
    let vcek = Certificate::from_der(&vcek_bytes).unwrap().into();

    // 2. Verify that the attestation was signed by the AMD root certificate
    sevtool::verify_attestation_report_raw(cpu_attestation, vcek, false);

    // 3. Verify the AMD root certificate
    let root_cert_url = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain";
    let root_cert_pem = requests::get(root_cert_url).unwrap().text().unwrap();

    // Convert PEM to DER to display a hash
    let root_cert_der = pem::parse(root_cert_pem.as_bytes()).unwrap();
    let root_cert_hash = ring::digest::digest(&ring::digest::SHA256, &root_cert_der.contents());

    println!("✅ Attestation is signed by root AMD certificate.",);
    println!("   Cert URL:  {}", root_cert_url);
    println!("   Cert Hash: 0x{}", hex::encode(&root_cert_hash));

    // B: Check CPU-signed measurement against protocol expected measurement
    // 1. Parse the protocol document
    let protocol_json: serde_json::Value = serde_json::from_str(&protocol_document).unwrap();
    let expected_measurement_base64 = protocol_json["expected_measurement"].clone().to_string();
    let expected_measurement = base64::decode(&expected_measurement_base64).unwrap();

    let mut expected_measurement_bytes: [u8; 48] = [0; 48];
    if expected_measurement.len() == expected_measurement_bytes.len() {
        expected_measurement_bytes.copy_from_slice(&expected_measurement);
    } else {
        panic!("Expected measurement length does not match.");
    }

    if cpu_attestation.measurement == expected_measurement_bytes {
        println!("✅ CPU-signed measurement matches the protocol expected measurement.");
    } else {
        println!("❌ CPU-signed measurement does not match the protocol expected measurement.");
    }
}

fn main() {
    let attestation_host = "https://enclave.blyss.dev";
    let attestation_path = "/.well-known/appspecific/dev.blyss.enclave/attestation.json";
    let attestation_url = attestation_host.to_string() + attestation_path;
    let attestation_document = requests::get(&attestation_url).unwrap().text().unwrap();

    let protocol_host = "https://cdn.jsdelivr.net/gh/blyssprivacy/verifier/protocols/";
    let protocol_version = "0.0.2";
    let protocol_url = protocol_host.to_string() + "v" + protocol_version + ".json";
    let response = requests::get(&protocol_url).expect("Failed to fetch protocol document");
    if !response.status().is_success() {
        panic!("Failed to fetch protocol document at {}", protocol_url);
    }
    let protocol_document = response.text().expect("Failed to read response text");

    verify(attestation_url, protocol_document);
}
