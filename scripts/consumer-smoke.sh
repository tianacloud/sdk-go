#!/usr/bin/env bash
set -euo pipefail
# Validate the exported module, even inside a multi-repository workspace.
export GOWORK=off
sdk_root=$(cd "$(dirname "$0")/.." && pwd)
fixture_root=${1:-}
mkdir -p "$sdk_root/.artifacts"
smoke_root=$(mktemp -d "$sdk_root/.artifacts/consumer.XXXXXX")
trap 'rm -rf -- "$smoke_root"' EXIT
python3 "$sdk_root/scripts/export-source.py" "$smoke_root/sdk-go"
python3 "$sdk_root/scripts/check-public-source.py" "$smoke_root/sdk-go"
mkdir "$smoke_root/app"
cat > "$smoke_root/app/go.mod" <<'MOD'
module example.com/tiana-consumer

go 1.25.0

require github.com/tianacloud/sdk-go v0.0.0

replace github.com/tianacloud/sdk-go => ../sdk-go
MOD
cp "$smoke_root/sdk-go/examples/echo/main.go" "$smoke_root/app/main.go"
mkdir -p "$smoke_root/app/cmd/auth-smoke"
cat > "$smoke_root/app/cmd/auth-smoke/main.go" <<'GO'
package main

import (
 "context"
 "fmt"
 "os"
 "time"

 "github.com/tianacloud/sdk-go/auth"
)

func main() {
 if len(os.Args) != 2 { panic("isolated state directory required") }
 if err := os.Setenv("XDG_CONFIG_HOME", os.Args[1]); err != nil { panic(err) }
 const origin = "https://mgr.example.test"
 store, err := auth.NewCredentialStore(origin)
 if err != nil { panic(err) }
 if err := store.Save(auth.Credential{AccessToken:"synthetic-access", RefreshToken:"synthetic-refresh", ExpiresAt:time.Now().Add(time.Hour)}); err != nil { panic(err) }
 client, err := auth.New(origin)
 if err != nil { panic(err) }
 credential, err := client.EnsureCredential(context.Background())
 if err != nil || credential.AccessToken != "synthetic-access" { panic("account store compatibility failed") }
 if err := store.Delete(); err != nil { panic(err) }
 fmt.Println("Independent auth consumer: PASS")
}
GO
(cd "$smoke_root/app" && go mod tidy && go build -o "$smoke_root/echo" .)
(cd "$smoke_root/app" && go build -o "$smoke_root/auth-smoke" ./cmd/auth-smoke)
"$smoke_root/auth-smoke" "$smoke_root/auth-state"
if [[ -z "$fixture_root" ]]; then
  (cd "$smoke_root/sdk-go" && TIANA_CONSUMER_BINARY="$smoke_root/echo" \
    go test -mod=readonly -run '^TestConsumerEcho$' -count=1 -timeout 30s -v .)
else
  python3 - "$fixture_root" "$smoke_root/echo" <<'PY'
import json, os, pathlib, subprocess, sys
fixture = pathlib.Path(sys.argv[1]).resolve()
ready = json.loads((fixture / 'ready.json').read_text())
env = {k: v for k, v in os.environ.items() if not k.startswith('TIANA_')}
env.update(TIANA_ENDPOINT=ready['endpoint'],
           TIANA_GATEWAY_ADDRESS=ready['token_address'],
           TIANA_CA_FILE=str(fixture / 'fixtures/gateway.pem'),
           TIANA_TOKEN=(fixture / 'fixtures/synthetic-token.txt').read_text().strip())
payload = b'consumer-go\x00\xff' * 8192
result = subprocess.run([sys.argv[2]], input=payload, env=env,
                        capture_output=True, timeout=15)
if result.returncode != 0:
    raise SystemExit(f'consumer failed: exit={result.returncode}, stderr_bytes={len(result.stderr)}')
assert result.stdout == ready['greeting'].encode() + payload + ready['eof_tail'].encode()
assert not result.stderr
print('External fixture consumer echo: PASS')
PY
fi
printf 'Current-source independent consumer: PASS\n'
