#!/usr/bin/env bash
set -euo pipefail
# No host installations. Works with Docker or the Podman Docker-compatible CLI.
engine="${CONTAINER_ENGINE:-docker}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
name="zitadel-compat-$$"
cleanup() {
  "$engine" rm -f "$name-test" "$name-zitadel" "$name-db" >/dev/null 2>&1 || true
  "$engine" volume rm "$name-state" >/dev/null 2>&1 || true
  "$engine" network rm "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
"$engine" network create "$name" >/dev/null
"$engine" volume create "$name-state" >/dev/null
"$engine" run --rm -v "$name-state:/state" -v "$root/tests/compat/prepare.sh:/prepare.sh:ro" golang:1.27.4-bookworm bash /prepare.sh
"$engine" run -d --name "$name-db" --network "$name" --network-alias db --tmpfs /var/lib/postgresql/data -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=disposable-test-password postgres:17.6-bookworm >/dev/null
ready=false
for attempt in $(seq 1 60); do
  if "$engine" exec "$name-db" pg_isready -U postgres >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [ "$ready" != true ]; then echo 'Test database failed to start' >&2; exit 1; fi
"$engine" run -d --name "$name-zitadel" --network "$name" --network-alias zitadel -v "$name-state:/state:ro" -e ZITADEL_MASTERKEY=MasterkeyNeedsToHave32Characters ghcr.io/zitadel/zitadel:v4.19.2 start-from-init --config /state/zitadel.yaml --masterkeyFromEnv --tlsMode enabled >/dev/null
"$engine" run --name "$name-test" --network "$name" -v "$name-state:/state" -v "$root:/src:ro" -w /work -e SSL_CERT_FILE=/state/tls.crt -e COMPAT_ISSUER=https://zitadel:8080 -e GOWORK=off golang:1.27.4-bookworm bash -ec '
  cp -a /src/. /work/
  export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.24.2-0.20260925035230-4d452bc0517c use 1.34.1 -p path)"
  go test -tags=compat -v ./tests/compat -count=1 -timeout=10m
'
