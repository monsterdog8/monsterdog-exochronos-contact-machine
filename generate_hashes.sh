#!/bin/bash
set -euo pipefail

find real_contact_logs -type f -print0 | sort -z | xargs -0 sha256sum > artifact_hashes.txt

sha256sum -c artifact_hashes.txt > hash_verify.log 2>&1 || true
