use base64;
// use pem::parse;
use reqwest::blocking as requests;
use ring;
use serde::Deserialize;
use serde_json;
use sev::{certs::snp::Certificate, firmware::guest::AttestationReport};

mod protocol;
mod sevtool;

#[derive(Debug, Deserialize)]
struct AugementedReport {
    #[serde(flatten)]
    report: AttestationReport,
    vcek: String,
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
    let expected_measurement_base64: String = serde_json::from_value(
        protocol_json
            .get("requirements")
            .and_then(|r| r.get("measurement"))
            .unwrap()
            .clone(),
    )
    .unwrap();
    println!(
        "expected_measurement_base64: {}",
        expected_measurement_base64
    );
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

use clap::Parser;

/// Standalone verifier for a Blyss-protocol attestation document.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// domain name of the server to verify
    #[arg(short, long)]
    domain: String,

    /// file path to an attestation document, which we'll expect the server to match
    #[arg(short, long, default_value = None)]
    protocol_path: Option<String>,
}

fn main() {
    let args = Args::parse();

    const ATTESTATION_PATH: &str = "/.well-known/appspecific/dev.blyss.enclave/attestation.json";
    let attestation_document = requests::get(args.domain + ATTESTATION_PATH)
        .unwrap()
        .text()
        .unwrap();

    let protocol_document;
    if let Some(path) = args.protocol_path {
        protocol_document = std::fs::read_to_string(path).unwrap();
    } else {
        let protocol_version = "0.0.2";
        protocol_document = protocol::get_online_protocol(protocol_version);
    }

    verify(attestation_document, protocol_document);
}
