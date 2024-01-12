`blyss_verifier` is a Python package that verifies the confidentiality claims of the Blyss confidential AI service at [enclave.blyss.dev](https://enclave.blyss.dev). For more details, see [this technical deep-dive](https://blog.blyss.dev/confidential-ai-from-gpu-enclaves/).

## Usage

Install with:

```bash
pip install --upgrade blyss-verifier
```

Verify the confidentiality claims of `enclave.blyss.dev` in a single command:

```bash
python -m blyss_verifier.verify
```

The verbose output (enabled with `-v`) includes more details on 
what images and hashes were computed and checked.
You can check a different URL by supplying it at the command line with:

```bash
python -m blyss_verifier.verify https://example.com
```

You can also use the library from within a Python script:

```py
from blyss_verifier.verify import verify_url
verify_url("https://enclave.blyss.dev")
```

## Example run

A typical run of the script will produce output like this:
```
Verifying claims for https://enclave.blyss.dev:
✅ Attestation is signed by root AMD certificate at:
   https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain (e6ecc853…d777aca3)

✅ Docker images match expected values:
   - Application: vllm/vllm-openai
   - UI: blintzbase/chatui
   - Shim: blintzbase/shim

✅ Disk is checked by dm-verity against the expected hash
   dm-mod.create="dmverity,,0,ro,0 …c51b4b94…809b8190… 1 panic_on_corruption"

✅ Attested kernel command line complies with protocol version v0.0.1

✅ Attested measurement matches expected measurement
   1ee2a500…3704131a == 1ee2a500…3704131a

✅ Certificate fingerprint matches attestation

✅ Included in at least two transparency logs:
   - Let's Encrypt 'Oak2024H1' log
   - Google 'Argon2024' log

✅ PASS
```

Let's break down what is happening in each step. 
For more details, please read [our technical deep-dive](https://blog.blyss.dev/confidential-ai-from-gpu-enclaves/).

```
✅ Attestation is signed by root AMD certificate at:
   https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain (e6ecc853…d777aca3)
```

First, we check that the attestation presented by the service,
at `https://enclave.blyss.dev/.well-known/appspecific/dev.blyss.enclave/attestation.json`,
is correctly signed by a chain of certificates leading to the root AMD certificate.
This ensures we are running genuine AMD secure hardware, and that all code is running inside
and AMD SEV-SNP secure VM.

```
✅ Docker images match expected values:
   - Application: vllm/vllm-openai
   - UI: blintzbase/chatui
   - Shim: blintzbase/shim
```

The kernel command-line, which is attested, specifies the Docker images
that the VM to launch at boot. Here, we check that these images are the ones 
we expect:
- `application`: Runs LLM's, and contains the model and the hash of the model weights.
- `ui`: Serves the web chat UI.
- `shim`: Verifies GPU attestation, requests
certficiates from Let's Encrypt, and proxies requests to the application.

```
✅ Disk is checked by dm-verity against the expected hash
   dm-mod.create="dmverity,,0,ro,0 …c51b4b94…809b8190… 1 panic_on_corruption"
```

The disk is hashed using dm-verity at boot, a Linux kernel module, and checked against a preset hash.
The image contains a minimal Ubuntu installation supporting Docker and the NVIDIA Container Toolkit.

```
✅ Attested kernel command line complies with protocol version v0.0.1
```

A *protocol* specifes the set of disk hashes, Docker images and launch arguments,
and firmware, initrd, and kernel hashes, that a client and server agree are valid for confidentiality to hold.
We outline `v0.0.1` of the protocol in `protocol/v0.0.1.json`, and leave future versions to be specified through
between end users, service providers, and security researchers.

```
✅ Attested measurement matches expected measurement
   1ee2a500…3704131a == 1ee2a500…3704131a
```

```
✅ Certificate fingerprint matches attestation
```

The verifier checks that the TLS certificate presented by the server matches 
the one specified by the signed attestation report.

```
✅ Included in at least two transparency logs:
   - Let's Encrypt 'Oak2024H1' log
   - Google 'Argon2024' log
```
The verifier checks that the certificate issued by Let's Encrypt was properly included in Certificate Transparency logs, 
and a permanent record of its issuance is committed to the log.

```
✅ PASS
```
Finally, once verification passes, clients can be sure that:
- The server's private key, used to establish all TLS connections to it, was generated on boot from inside the secure VM, and is inaccessible to Blyss or any other third party.
- The server's GPU was in confidential computing mode, and all data transfers over PCIe were encrypted using keys known only to the secure VM and the GPU's secure hardware.
- The contents of any interaction with the API are inaccessible to Blyss or any other third party.