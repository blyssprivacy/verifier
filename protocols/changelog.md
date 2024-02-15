### 0.0.2
Added launch digest to expected firmware measurement.
The launch digest is computed from the kernel, initrd, cmdline, and ovmf. If any of the inputs change, the launch digest will not reproduce.
We pin it in the protocol to support clients that don't implement sev-snp-measure (original is in Python, ports to other platforms pending).

### 0.0.1
First confidential AI measurement set. Enables GPU-accelerated LLM inference.