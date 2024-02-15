import json
import argparse
from typing import Any
import shlex


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


def protocol_to_kernelcli(protocol: dict[str, Any]):
    """Render a protocol to its corresponding kernel command line."""

    args = []

    # Ensure that the enclave VM enforces disk integrity checks
    disk_info = protocol["requirements"]["firmware"]["disk"]
    disk_bytes = int(disk_info["size"])
    disk_blocks = disk_bytes // 4096
    disk_sectors = disk_bytes // 512
    disk_check_seq = f'fsck.mode=skip ro console=ttyS0 overlayroot=tmpfs root=/dev/dm-0 rootflags=noload dm-mod.create=\\"dmverity,,0,ro,0 {disk_sectors} verity 1 /dev/sda2 /dev/sdb 4096 4096 {disk_blocks} 1 sha256 {disk_info["hash"]} {str(0) * 64} 1 panic_on_corruption\\"'
    args.append(disk_check_seq)

    launch_params = protocol["requirements"]["launch"]

    # Docker images
    for k, v in launch_params["docker"].items():
        docker_image = v["image"]
        if v.get("digest"):
            docker_image += "@" + v["digest"]
        elif v.get("tag"):
            docker_image += ":" + v["tag"]
        else:
            print({k: v})
            raise ValueError("Invalid protocol: Docker image must have a tag or digest")

        # coerce envs, image, and args to lists of strings to avoid extra spaces when one of them is empty
        docker_envs = [f"--env {env}" for env in v.get("env", [])]
        docker_args = [f" {arg}" for arg in v.get("args", [])]
        docker_sequence = " ".join(docker_envs + [docker_image] + docker_args)

        docker_cli = f'{k}=\\"{docker_sequence}\\"'
        args.append(docker_cli)

    # Security controls e.g. disable SSH
    if launch_params.get("security"):
        args.append(launch_params["security"])

    # static suffix
    args.append("initrd=initrd")

    reconstructed_kernelcli = " ".join(args)
    return reconstructed_kernelcli


if __name__ == "__main__":
    import json

    import argparse

    parser = argparse.ArgumentParser(description="Load protocol from JSON file")
    parser.add_argument(
        "protocol_path", type=str, help="Path to the protocol JSON file"
    )
    args = parser.parse_args()

    with open(args.protocol_path, "r") as file:
        protocol = json.load(file)
    kernel_cli = protocol_to_kernelcli(protocol)
    print(kernel_cli)
