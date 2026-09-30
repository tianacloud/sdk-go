#!/usr/bin/env python3
"""Build the selected Gateway loopback fixture, then run Go/Node interoperability tests."""
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

sdk = Path(__file__).resolve().parents[1]
if len(sys.argv) not in (2, 3):
    raise SystemExit("usage: python3 scripts/test-gateway.py /path/to/gateway-checkout [/path/to/sdk-node-checkout]")
gateway = Path(sys.argv[1]).resolve()
head = subprocess.check_output(["git", "-C", str(gateway), "rev-parse", "HEAD"], text=True).strip()
dirty = bool(subprocess.check_output(["git", "-C", str(gateway), "status", "--porcelain"]))
node_sdk = Path(sys.argv[2]).resolve() if len(sys.argv) == 3 else None
build_env = dict(os.environ, CARGO_TARGET_DIR=str(gateway / "target"))
artifacts = sdk / ".artifacts"
artifacts.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="gateway-", dir=artifacts) as directory:
    root = Path(directory)
    (root / "fixtures").mkdir()
    shutil.copyfile(sdk / "testdata/tls/endpoint_certificate.pem", root / "fixtures/gateway.pem")
    (root / "fixtures/synthetic-token.txt").write_text("tia_0" + "A" * 43 + "\n")
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
    build = subprocess.run(["cargo", "build", "--offline", "--message-format=json",
                            "--manifest-path", str(root / "Cargo.toml")],
                           stdout=subprocess.PIPE, text=True, env=build_env)
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
    env = dict(os.environ, GOWORK="off", TIANA_GATEWAY_FIXTURE=str(root),
               TIANA_GATEWAY_SOURCE_REVISION=head, TIANA_GATEWAY_SOURCE_DIRTY=str(dirty).lower())
    process = subprocess.Popen([executable, str(root)], env=env)
    try:
        deadline = time.monotonic() + 15
        while not (root / "ready.json").exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("Gateway fixture failed to become ready")
            time.sleep(0.05)
        subprocess.run(["go", "test", "-race", "-tags=integration", "-run", "^TestGatewaySnapshot$", "-count=1", "-timeout=90s", "-v", "."], cwd=sdk, env=env, check=True)
        subprocess.run(["bash", "scripts/consumer-smoke.sh", str(root)], cwd=sdk, env=env, check=True)
        if node_sdk is not None:
            subprocess.run(["node", "scripts/gateway-smoke.mjs", str(root)], cwd=node_sdk, env=env, check=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
print(f"Gateway {head} dirty={dirty} source interoperability: PASS (not published-artifact validation)")
