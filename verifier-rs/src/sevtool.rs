use hex;
use openssl::x509::X509;
use sev::{
    certs::snp::{ca, Certificate, Chain, Verifiable},
    firmware::{guest::AttestationReport, host::TcbVersion},
};

/// The AMD Genoa ARK and ASK certificates.
pub const GENOA_PEM: &'static [u8] = include_bytes!("../data/Genoa.pem");

/// The AMD SEV-SNP product name for Genoa.
pub const SEV_PROD_NAME: &str = "Genoa";

/// The AMD Key Distribution Service (KDS) URL.
pub const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";

/// The AMD Key Distribution Service (KDS) VCEK endpoint.
pub const KDS_VCEK: &str = "/vcek/v1";

const _KDS_CERT_CHAIN: &str = "cert_chain";

/// Requests the main AMD SEV-SNP certificate chain.
///
/// This is the chain of certificates up to the AMD Root Key (ARK).
/// The order is (chip) -> (vcek) -> (ask) -> (ark).
/// These may be used to verify the downloaded VCEK is authentic.
pub fn get_cert_chain(sev_prod_name: &str) -> ca::Chain {
    // The chain can be retrieved at "https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain"
    // let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{KDS_CERT_CHAIN}");
    // let pem = reqwest::blocking::get(&url).unwrap().bytes().unwrap().to_vec();

    if sev_prod_name != SEV_PROD_NAME {
        panic!("Only Genoa is supported at this time");
    }

    let chain = X509::stack_from_pem(&GENOA_PEM).unwrap();

    // Create a certificate chain with the ARK and ASK
    let (ark, ask) = (&chain[1].to_pem().unwrap(), &chain[0].to_pem().unwrap());
    let cert_chain = ca::Chain::from_pem(ark, ask).unwrap();

    cert_chain
}

/// Requests the VCEK for the specified chip and TCP.
///
/// The VCEK is the "Versioned Chip Endorsement Key" for a particular chip and TCB.
/// It is used to verify the authenticity of the attestation report.
///
/// The VCEK is retrieved from the AMD Key Distribution Service (KDS),
/// and generated on the first request to the service. The returned certificate is
/// valid for 7 years from issuance.
///
/// This function returns the VCEK as a DER-encoded X509 certificate.
pub fn request_vcek(chip_id: [u8; 64], reported_tcb: TcbVersion, sev_prod_name: &str) -> Vec<u8> {
    let hw_id = hex::encode(&chip_id);
    let url = format!(
    "{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode,
        );
    // println!("Requesting VCEK from: {url}\n");
    let rsp_bytes = reqwest::blocking::get(&url)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
    rsp_bytes
}

/// Verifies an attestation report, using the provided report JSON string and VCEK bytes.
///
/// Verification intentionally fails if `fail_on_purpose` is true.
pub fn verify_attestation_report(report_json: &str, vcek_bytes: &[u8], fail_on_purpose: bool) {
    let report: AttestationReport = serde_json::from_str(report_json).unwrap();
    let vcek = Certificate::from_der(vcek_bytes).unwrap().into();

    verify_attestation_report_raw(report, vcek, fail_on_purpose);
}

/// Verifies an attestation report, using the provided report and VCEK.
///
/// Verification intentionally fails if `fail_on_purpose` is true.
pub fn verify_attestation_report_raw(
    mut report: AttestationReport,
    vcek: Certificate,
    fail_on_purpose: bool,
) {
    if fail_on_purpose {
        report.measurement[0] = report.measurement[0].wrapping_add(1);
    }

    // Get the ARK and ASK certificates
    let cert_chain = get_cert_chain(SEV_PROD_NAME);

    // Create the full certificate chain
    let full_cert_chain = Chain {
        ca: cert_chain,
        vcek,
    };

    // Verify the full certificate chain (VCEK -> ASK -> ARK), and then
    // check that the attestation report is signed by the VCEK.
    let verification_result = (&full_cert_chain, &report).verify();

    // Panic with detailed error if failed
    verification_result.unwrap();
}
