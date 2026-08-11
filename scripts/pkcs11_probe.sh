#!/usr/bin/env bash
set -euo pipefail
M="${PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
pcsc_scan || true
opensc-tool -l
opensc-tool -a || true
pkcs11-tool --module "$M" -L
pkcs11-tool --module "$M" -M
pkcs11-tool --module "$M" -O
