# Verifier
This repository contains code that verifies the confidentiality claims of 
the Blyss confidential AI service at [enclave.blyss.dev](https://enclave.blyss.dev). For more details, see [this technical deep-dive](https://blog.blyss.dev/confidential-ai-from-gpu-enclaves/).

## Running
A confidentiality claim consists of several claimed code blobs:
- `application`: The Docker image hash and arguments to run the application, 
containing the model and the hash of the model weights.
- `ui`: The Docker image hash and arguments to serve the web chat UI,
hosted at [enclave.blyss.dev](https://enclave.blyss.dev).
- `shim`: The Docker image hash and arguments to run the shim, 
which contains the code that verifies GPU attestation, requests
certficiates from Let's Encrypt, and proxies requests to the application.
- `disk`: The disk image of the enclave, containing a minimal OS 
containing Docker and the NVIDIA Container Toolkit.
- `security`: Kernel command-line parameters that ensure security.

The claims can be represented as a JSON file, `claims.json`, which is
available at [enclave.blyss.dev/claims.json](https://enclave.blyss.dev/claims.json):
```json
{
  "application": "--env HUGGING_FACE_HUB_TOKEN=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 vllm/vllm-openai@sha256:d4b96484ebd0d81742f0db734db6b0e68c44e252d092187935216e0b212afc24 --model mistralai/Mistral-7B-Instruct-v0.1",
  "ui": "--env DEFAULT_MODEL=mistralai/Mistral-7B-Instruct-v0.1 --env OPENAI_API_HOST=https://enclave.blyss.dev --env NODE_TLS_REJECT_UNAUTHORIZED=0 blintzbase/chatui@sha256:19d393c7642e1e84be209139ed5459444e2e7a474eeb78e3cc16b30d36ac1cce",  
  "shim": "blintzbase/shim@sha256:f3716260a4ee595ff497ef12c183f58378cf85be0208b9c568062f2b092d4fb7",
  "disk": "fsck.mode=skip ro console=ttyS0 overlayroot=tmpfs root=/dev/dm-0 rootflags=noload dm-mod.create=\"dmverity,,0,ro,0 1046369920 verity 1 /dev/sda2 /dev/sdb 4096 4096 130796240 1 sha256 c51b4b94ee613a768cf555442582b9bcf6e8b04aacd26ff52cd69f87809b8190 0000000000000000000000000000000000000000000000000000000000000000 1 panic_on_corruption\"",
  "security": "systemd.mask=ssh.service"
}
```

To verify a given set of claims against an attestation file, run:
```bash
python verify.py --claims claims.json --attestation attestation.json
```

To check a live site, and print the verified claims, run:
```bash
python verify.py https://enclave.blyss.dev
```