import json
import argparse
from importlib import resources
import base64
import shlex
import hashlib
from contextlib import redirect_stdout
import OpenSSL.crypto

import requests

import sev_attest_tool

from sevsnpmeasure import vcpu_types
from sevsnpmeasure.sev_mode import SevMode
from sevsnpmeasure.gctx import GCTX
from sevsnpmeasure.ovmf import OVMF
from sevsnpmeasure.sev_hashes import SevHashes
from sevsnpmeasure.vmsa import VMSA
from sevsnpmeasure.sev_mode import SevMode
from sevsnpmeasure.vmm_types import VMMType
from sevsnpmeasure.guest import snp_update_metadata_pages

from ctutlz.ctlog import download_log_list, Logs, set_operator_names
from ctutlz.scripts.verify_scts import verify_scts_by_cert
from ctutlz.tls.handshake import do_handshake

DEFAULT_URL = "https://enclave.blyss.dev"

ATTESTATION_PATH = "/.well-known/appspecific/dev.blyss.enclave/attestation.json"

DEFAULT_PROTOCOL = "v0.0.1"

ovmf_file_path_prefix = str(resources.files("blyss_verifier") / "data" / "OVMF_")


def parse_kernel_cli_parameters(cli_string):
    """Parses a string containing kernel command-line parameters."""
    args = shlex.split(cli_string)
    params = {}

    for arg in args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            params[key] = value
        else:
            params[arg] = True

    return params


def snp_calc_launch_digest(
    vcpus_num: int,
    append_str: str,
    kernel_hash: str,
    initrd_hash: str,
    ovmf_file: str,
    vcpu_sig: int = vcpu_types.CPU_SIGS["EPYC-v4"],
    vmm_type: VMMType = VMMType.QEMU,
) -> bytes:
    """
    Calculate the launch digest for a SEV-SNP guest.
    """

    gctx = GCTX()
    ovmf = OVMF(ovmf_file)

    # Hashes the OVMF
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())

    # SHA256 the kernel command line + null terminator
    append_hash = hashlib.sha256(append_str.encode() + b"\x00").digest()

    # Load hashes
    sev_hashes = SevHashes(ovmf_file, None, None)  # dummy hash for kernel for here
    sev_hashes.kernel_hash = bytes.fromhex(kernel_hash)
    sev_hashes.initrd_hash = bytes.fromhex(initrd_hash)
    sev_hashes.cmdline_hash = append_hash

    snp_update_metadata_pages(gctx, ovmf, sev_hashes, vmm_type)

    vmsa = VMSA(SevMode.SEV_SNP, ovmf.sev_es_reset_eip(), vcpu_sig, vmm_type)
    for vmsa_page in vmsa.pages(vcpus_num):
        gctx.update_vmsa_page(vmsa_page)

    return gctx.ld()


def verify_inclusion_in_transparency_log(url: str, cert_fingerprint: str):
    logs_dict = download_log_list()
    set_operator_names(logs_dict)
    ctlogs = Logs([logs_dict])

    if url.startswith("https://"):
        url = url[len("https://") :]

    # NB: silences debug output from the ctutlz library
    with redirect_stdout(None):
        # SCTs are in the certificate, not the TLS handshake
        handshake_res = do_handshake(url, scts_tls=False, scts_ocsp=False)

    ee_cert = handshake_res.ee_cert
    ee_cert_fingerprint = (
        ee_cert.pyopenssl.digest("sha256").decode().lower().replace(":", "")
    )
    assert (
        ee_cert_fingerprint == cert_fingerprint
    ), "Server presented a different certificate than the one attested"
    print("✅ Certificate fingerprint matches attestation\n")

    verifications = verify_scts_by_cert(handshake_res, ctlogs)

    for ver in verifications:
        assert ver.verified, "Certificate not verified by transparency log"

    assert (
        len(verifications) >= 2
    ), "Certificate not verified by at least two transparency logs"
    print("✅ Included in at least two transparency logs:")

    for ver in verifications:
        print(f"   - {ver.log.description}")
    print()


def get_protocl_reqs(protocol):
    protocol_spec = None
    protocol_spec_path = (
        str(resources.files("blyss_verifier") / "protocol" / protocol) + ".json"
    )
    with open(protocol_spec_path, "r") as f:
        protocol_spec = json.load(f)
    reqs = protocol_spec["requirements"]
    return reqs


def has_docker_image(docker_run_cli, expected_image):
    docker_run_args = shlex.split(docker_run_cli)
    i = 0
    while i < len(docker_run_args):
        arg = docker_run_args[i]
        if arg == "--env":
            i += 2
            continue
        i += 1

        # Check that arg is <expected_image>[@sha256:<hash>]
        if arg.startswith(expected_image):
            if "@" in arg:
                image, hash = arg.split("@")
                assert image == expected_image, "Docker image does not match expected"
                assert hash.startswith("sha256:"), "Docker image hash is not sha256"
            else:
                assert arg == expected_image, "Docker image does not match expected"
            return
        else:
            print(arg)
            raise ValueError("Docker image not found in kernel command line 1")

    raise ValueError("Docker image not found in kernel command line 2")


def complies_with_protocol(kernel_cli, protocol, verbose=False):
    kernel_cli_params = parse_kernel_cli_parameters(kernel_cli)
    reqs = get_protocl_reqs(protocol)

    if verbose:
        print("Checking compliance with protocol version ", protocol)

    # Application
    if "application" in reqs:
        assert "blyss_docker_img" in kernel_cli_params
        has_docker_image(kernel_cli_params["blyss_docker_img"], reqs["application"])
        if verbose:
            print("Got application docker image: ", reqs["application"])

    # UI
    if "ui" in reqs:
        assert "blyss_ui_docker_img" in kernel_cli_params
        has_docker_image(kernel_cli_params["blyss_ui_docker_img"], reqs["ui"])
        if verbose:
            print("Got UI docker image: ", reqs["ui"])

    # Shim
    if "shim" in reqs:
        assert "blyss_shim_docker_img" in kernel_cli_params
        has_docker_image(kernel_cli_params["blyss_shim_docker_img"], reqs["shim"])
        if verbose:
            print("Got shim docker image: ", reqs["shim"])
    print("✅ Docker images match expected values:")
    print(f'   - Application: {reqs["application"]}')
    print(f'   - UI: {reqs["ui"]}')
    print(f'   - Shim: {reqs["shim"]}\n')

    # Disk
    assert "firmware" in reqs
    assert reqs["firmware"]["disk"]["type"] == "dm_verity"
    disk_hash = reqs["firmware"]["disk"]["hash"]
    disk_bytes = int(reqs["firmware"]["disk"]["size"])
    disk_blocks = disk_bytes // 4096
    disk_sectors = disk_bytes // 512
    disk_check_seq = f'fsck.mode=skip ro console=ttyS0 overlayroot=tmpfs root=/dev/dm-0 rootflags=noload dm-mod.create="dmverity,,0,ro,0 {disk_sectors} verity 1 /dev/sda2 /dev/sdb 4096 4096 {disk_blocks} 1 sha256 {disk_hash} 0000000000000000000000000000000000000000000000000000000000000000 1 panic_on_corruption"'
    if verbose:
        print("kernel_cli", kernel_cli)
        print("disk_check_seq", disk_check_seq)
    assert disk_check_seq in kernel_cli, "Firmware does not match expected"
    print("✅ Disk is checked by dm-verity against the expected hash")
    print(
        f'   dm-mod.create="dmverity,,0,ro,0 …{disk_hash[:8]}…{disk_hash[-8:]}… 1 panic_on_corruption"\n'
    )

    # Security
    assert "security" in reqs
    assert reqs["security"] in kernel_cli

    # Reconstruction
    # Reconstruct the kernel command line from this minimum set, to check against extraneous parameters
    quote = lambda s: '"' + s + '"'
    reconstructed_kernel_cli_params = [
        reqs["security"],
        disk_check_seq,
        "blyss_shim_docker_img=" + quote(kernel_cli_params["blyss_shim_docker_img"]),
        "blyss_ui_docker_img=" + quote(kernel_cli_params["blyss_ui_docker_img"]),
        "blyss_docker_img=" + quote(kernel_cli_params["blyss_docker_img"]),
    ]
    reconstructed_kernel_cli = " ".join(reconstructed_kernel_cli_params)
    assert (
        reconstructed_kernel_cli == kernel_cli
    ), "Kernel command line does not match reconstruction, extraneous parameters found"

    return True


def verify_claims(claims, attestation, protocol="v0.0.1", url=None, verbose=False):
    reqs = get_protocl_reqs(protocol)

    # 1. Verify the attestation report
    vcek_base64 = attestation["cpu_attestation"]["vcek"]
    vcek_bytes = base64.b64decode(vcek_base64 + "==")
    sev_attest_tool.verify_attestation_report(
        json.dumps(attestation["cpu_attestation"]), vcek_bytes
    )
    root_cert_url = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
    root_cert_pem = requests.get(root_cert_url).content
    root_cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, root_cert_pem
    )
    root_cert_hash = hashlib.sha256(root_cert_pem).hexdigest()
    print(f"✅ Attestation is signed by root AMD certificate at:")
    print(f"   {root_cert_url} ({root_cert_hash[:8]}…{root_cert_hash[-8:]})\n")

    # 2. Assemble the kernel command line
    expected_kernel_cli = None
    if "kernel_cli" in claims:
        expected_kernel_cli = claims["kernel_cli"]
    elif "application" in claims:
        expected_kernel_cli = " ".join(
            [
                claims["security"],
                claims["disk"],
                claims["shim"],
                claims["ui"],
                claims["application"],
            ]
        )
    else:
        expected_kernel_cli = attestation["cpu_attestation"]["launch"]["kernel_cli"]

    # Remove the initrd=initrd parameter if it exists
    if "initrd=initrd" in expected_kernel_cli:
        expected_kernel_cli = expected_kernel_cli.replace(" initrd=initrd", "")

    if verbose:
        print("Got kernel command line: ", repr(expected_kernel_cli))

    # Verify that the kernel command line complies with the protocol requirements
    if not complies_with_protocol(expected_kernel_cli, protocol, verbose=verbose):
        raise ValueError(
            f"Kernel command line does not comply with protocol {protocol}"
        )
    print(f"✅ Attested kernel command line complies with protocol version {protocol}\n")

    # 3. Verify the OVMF file
    ovmf_file_path = ovmf_file_path_prefix + protocol + ".fd"
    if "-test" in protocol:
        ovmf_file_path = ovmf_file_path_prefix + (protocol.split("-")[0]) + ".fd"
    ovmf_hash = None
    with open(ovmf_file_path, "rb") as f:
        ovmf_file = f.read()
        expected_ovmf_file_hash = reqs["firmware"]["ovmf"]
        ovmf_hash = hashlib.sha256(ovmf_file).hexdigest()
        assert (
            ovmf_hash == expected_ovmf_file_hash
        ), "OVMF file hash does not match expected"

    # 4. Calculate the launch digest
    expected_launch_digest = snp_calc_launch_digest(
        vcpus_num=attestation["cpu_attestation"]["launch"]["num_vcpus"],
        append_str=expected_kernel_cli,
        kernel_hash=reqs["firmware"]["kernel"],
        initrd_hash=reqs["firmware"]["initrd"],
        ovmf_file=ovmf_file_path,
    )
    if verbose:
        print("Got # of vCPUS:", attestation["cpu_attestation"]["launch"]["num_vcpus"])
        print("Got kernel hash: ", reqs["firmware"]["kernel"])
        print("Got initrd hash: ", reqs["firmware"]["initrd"])
        print("Got OVMF hash: ", ovmf_hash)

    # 5. Check that the launch digest matches the attestation report
    if verbose:
        print("Expecting launch digest: ", expected_launch_digest.hex())
        print(
            "      Got launch digest: ",
            bytes(attestation["cpu_attestation"]["measurement"]).hex(),
        )
    assert (
        list(expected_launch_digest) == attestation["cpu_attestation"]["measurement"]
    ), "Launch digest does not match attestation report"
    print("✅ Attested measurement matches expected measurement")
    gold = expected_launch_digest.hex()
    gues = bytes(attestation["cpu_attestation"]["measurement"]).hex()
    print(f"   {gold[:8]}…{gold[-8:]} == {gues[:8]}…{gues[-8:]}\n")

    # 6. Check that this certificate is in the transparency log
    if url:
        attested_cert_fingerprint = bytes(
            attestation["cpu_attestation"]["report_data"]
        )[:32].hex()
        if verbose:
            print(
                "Checking inclusion in transparency log of cert with fingerprint:",
                attested_cert_fingerprint,
            )
        verify_inclusion_in_transparency_log(url, attested_cert_fingerprint)

    print("✅ PASS")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", type=str, default=DEFAULT_URL, nargs="?")
    parser.add_argument("--attestation", type=str, default=None)
    parser.add_argument("--protocol", type=str, default=DEFAULT_PROTOCOL)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    attestation = None
    if not args.attestation:
        assert args.url, "Must specify (claims.json + attestation.json) or url"
        attestation = requests.get(args.url + ATTESTATION_PATH).json()
        print(f"Verifying claims for {args.url}:")
    else:
        with open(args.attestation, "r") as f:
            attestation = json.load(f)

    verify_claims({}, attestation, args.protocol, url=args.url, verbose=args.verbose)


def verify_url(url, verbose=False):
    attestation = requests.get(url + ATTESTATION_PATH).json()
    verify_claims({}, attestation, DEFAULT_PROTOCOL, url=url, verbose=verbose)


# example:
# python3 verify_claims.py https://example.com --attestation data/test_full_attestation.json --protocol v0.0.1-test

if __name__ == "__main__":
    main()
