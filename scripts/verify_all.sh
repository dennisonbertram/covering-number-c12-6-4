#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verification_root="${repo_root}/.verification"
toolchain_build="${C1264_TOOLCHAIN_BUILD_DIR:-${repo_root}/.toolchain-build}"
drat_archive="${C1264_FIXED_LINK_DRAT_ARCHIVE:-}"
lrat_archive="${C1264_FIXED_LINK_LRAT_ARCHIVE:-}"
mkdir -p "${verification_root}"

if [[ -n "${drat_archive}" && -z "${lrat_archive}" ]] ||
   [[ -z "${drat_archive}" && -n "${lrat_archive}" ]]; then
  echo "Set both C1264_FIXED_LINK_DRAT_ARCHIVE and C1264_FIXED_LINK_LRAT_ARCHIVE, or neither." >&2
  exit 1
fi

manifest_status=0
if python3 "${repo_root}/scripts/verify_release_manifest.py"; then
  manifest_status=0
else
  manifest_status=$?
  if [[ "${manifest_status}" -ne 2 ]]; then
    exit "${manifest_status}"
  fi
fi

python3 "${repo_root}/scripts/verify_cover_41.py"

python3 "${repo_root}/certificates/local/audit_degree5_cnf.py" \
  "${repo_root}/certificates/local/degree5.cnf" \
  "${repo_root}/certificates/local/degree5.map.json"

c++ -O2 -std=c++20 \
  "${repo_root}/certificates/local/check_c1042_degree5.cpp" \
  -o "${verification_root}/check_c1042_degree5"
"${verification_root}/check_c1042_degree5"

python3 "${repo_root}/certificates/functional/audit_gate_roots.py"

python3 \
  "${repo_root}/certificates/compact-encoder-audit/verify_frozen_audit.py"

python3 -S \
  "${repo_root}/certificates/compact-leaf-extension-audit/audit_leaf_extensions.py" \
  --campaign-root "${repo_root}/certificates/global/compact_campaign" \
  --report "${verification_root}/compact-leaf-extension-audit.json"

python3 "${repo_root}/scripts/audit_global_roots.py" \
  --artifact-dir "${repo_root}/certificates/global"

python3 -S \
  "${repo_root}/certificates/fixed-link-campaign/audit_fixed_link_classification.py" \
  --artifact-dir "${repo_root}/certificates/fixed-link-campaign" \
  --base \
    "${repo_root}/certificates/global/compact_campaign/global_base.cnf" \
  --report "${verification_root}/fixed-link-campaign-audit.json"

python3 -S \
  "${repo_root}/certificates/fixed-link-proof/verify_structural.py" \
  --repo-root "${repo_root}"

C1264_TOOLCHAIN_BUILD_DIR="${toolchain_build}" \
  "${repo_root}/toolchain/build-replay.sh"
zstd -q -d -f \
  "${repo_root}/certificates/local/degree5.lrat.zst" \
  -o "${verification_root}/degree5.lrat"
"${toolchain_build}/lrat-check" \
  "${repo_root}/certificates/local/degree5.cnf" \
  "${verification_root}/degree5.lrat"

if [[ -x "${toolchain_build}/cake_lpr" ]]; then
  env CML_HEAP_SIZE=8192 CML_STACK_SIZE=2048 \
    "${toolchain_build}/cake_lpr" \
    "${repo_root}/certificates/local/degree5.cnf" \
    "${verification_root}/degree5.lrat"
fi

if [[ "${manifest_status}" -eq 2 ]]; then
  echo "RELEASE MANIFEST PENDING: full release verification cannot pass" >&2
  exit 2
fi

if [[ -z "${drat_archive}" ]]; then
  python3 -S \
    "${repo_root}/certificates/fixed-link-classification/verify_frozen_classification.py" \
    --candidate-representatives \
      "${repo_root}/certificates/fixed-link-campaign/link_representatives.txt"
  echo "STRUCTURAL VERIFICATION PASSED, BUT FULL RELEASE REPLAY WAS NOT RUN." >&2
  echo "Set both fixed-link archive environment variables; this is not a completion gate." >&2
  exit 2
fi

if [[ ! -x "${toolchain_build}/cake_lpr" ]]; then
  echo "Full replay requires the pinned Arm64 CakeML checker." >&2
  exit 1
fi

zstd_command="$(command -v zstd || true)"
if [[ -z "${zstd_command}" ]]; then
  echo "Full replay requires zstd." >&2
  exit 1
fi
zstd_real="$(
  python3 -S -c \
    'import os, sys; print(os.path.realpath(sys.argv[1]))' \
    "${zstd_command}"
)"

python3 -S \
  "${repo_root}/certificates/fixed-link-proof/verify_public_release.py" \
  --repo-root "${repo_root}" \
  --release-assets \
    "${repo_root}/certificates/fixed-link-proof/release-assets.json" \
  --drat-archive "${drat_archive}" \
  --lrat-archive "${lrat_archive}" \
  --lrat-check "${toolchain_build}/lrat-check" \
  --cake-lpr "${toolchain_build}/cake_lpr" \
  --zstd "${zstd_real}"

echo "ALL RELEASE VERIFICATION GATES PASSED"
