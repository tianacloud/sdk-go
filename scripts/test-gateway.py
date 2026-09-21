#!/usr/bin/env python3
"""Build the pinned Gateway loopback fixture, then run Go interoperability tests."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

COMMIT = "9f5aa69b24aa6e04112baaf8d1e17c0639fd293b"
sdk = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    raise SystemExit("usage: python3 scripts/test-gateway.py /path/to/gateway-checkout")
gateway = Path(sys.argv[1]).resolve()
# Require the pinned clean Gateway Git checkout.
head = subprocess.check_output(["git", "-C", str(gateway), "rev-parse", "HEAD"], text=True).strip()
if head != COMMIT:
    raise SystemExit(f"Gateway checkout must be at {COMMIT}")
if subprocess.check_output(["git", "-C", str(gateway), "status", "--porcelain"]):
    raise SystemExit("Gateway checkout must be clean")
artifacts = sdk / ".artifacts"
artifacts.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="gateway-", dir=artifacts) as directory:
    root = Path(directory)
    (root / "fixtures").mkdir()
    shutil.copyfile(sdk / "testdata/tls/endpoint_certificate.pem", root / "fixtures/gateway.pem")
    (root / "fixtures/synthetic-token.txt").write_text("tia_" + "A" * 43 + "\n")
    for name, source in [("cert", "endpoint_certificate.pem"), ("key", "endpoint_key.pem")]:
        pem = (sdk / "testdata/tls" / source).read_bytes()
        match = re.search(rb"-----BEGIN [^-]+-----\s*(.*?)\s*-----END [^-]+-----", pem, re.S)
        if not match:
            raise SystemExit("invalid synthetic PEM fixture")
        (root / (name + ".der")).write_bytes(base64.b64decode(match[1]))
    shutil.copyfile(sdk / "scripts/gateway-fixture.rs", root / "main.rs")
    cargo = ['[package]', 'name = "sdk-gateway-fixture"', 'version = "0.0.0"', 'edition = "2024"',
             '[workspace]', '[[bin]]', 'name = "sdk-gateway-fixture"', 'path = "main.rs"', '[dependencies]']
    for name in ["gateway-protocol", "gateway-public", "gateway-runtime", "gateway-services"]:
        cargo.append(name + " = { path = " + json.dumps(str(gateway / "crates" / name)) + " }")
    cargo.extend(['tokio = { version = "=1.53.1", features = ["macros", "rt-multi-thread", "io-util", "net", "time"] }',
                  'serde_json = "=1.0.151"'])
    (root / "Cargo.toml").write_text("\n".join(cargo) + "\n")
    # Preserve the Gateway's dependency resolution for the shared crates.
    shutil.copyfile(gateway / "Cargo.lock", root / "Cargo.lock")
    # Cargo configuration can change both the target directory and triple.
    # Use the artifact emitted by this build, never a guessed/stale binary.
    build = subprocess.run(["cargo", "build", "--message-format=json",
                            "--manifest-path", str(root / "Cargo.toml")],
                           stdout=subprocess.PIPE, text=True)
    executable = None
    for line in build.stdout.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-message":
            rendered = message.get("message", {}).get("rendered")
            if rendered:
                print(rendered, end="", file=sys.stderr)
        if (message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "sdk-gateway-fixture"
                and message.get("executable")):
            executable = message["executable"]
    build.check_returncode()
    if executable is None:
        raise SystemExit("Cargo did not report the Gateway fixture executable")
    process = subprocess.Popen([executable, str(root)])
    try:
        deadline = time.monotonic() + 15
        while not (root / "ready.json").exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("Gateway fixture failed to become ready")
            time.sleep(0.05)
        env = dict(os.environ, TIANA_GATEWAY_FIXTURE=str(root))
        subprocess.run(["go", "test", "-race", "-tags=integration", "-run", "^TestGatewaySnapshot$", "-count=1", "-timeout=90s", "-v", "."], cwd=sdk, env=env, check=True)
        subprocess.run(["bash", "scripts/consumer-smoke.sh", str(root)], cwd=sdk, env=env, check=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
print(f"Gateway {COMMIT} interoperability: PASS")
