#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_root="${C1264_TOOLCHAIN_BUILD_DIR:-${repo_root}/.toolchain-build}"
drat_commit="2e3b2dc0ecf938addbd779d42877b6ed69d9a985"
cadical_commit="38e073b389a877b0a0d3c91136d2443ab95fdeba"
lrat_check_sha="bf07c2ac96b9035da1ebcc578cb95e956a2b795629d613154cdb307f8a8f4a95"
drat_license_sha="71ab2a9dc5a294ad8fba4ccb8c45aaa8a439596d314a2a046ac9b62266872a18"
cake_asm_sha="95b64883edc0cb09feedbcb1ebec233e2490f5b458fdda9dc29c212ed916f00c"
cake_ffi_sha="8e30d84fdcb2177aa5571d7fa6661a2fae5ecfd56baa0ce49c65f9233a9f87cb"
cake_license_sha="eb1e4ff71900d55d384ff18afad5aae48417ce0fff25231565862c42b45e5dbc"

mkdir -p "${build_root}"

check_sha256() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(shasum -a 256 "${path}" | awk '{print $1}')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "SHA-256 mismatch: ${path}" >&2
    echo "expected ${expected}" >&2
    echo "actual   ${actual}" >&2
    exit 1
  fi
}

check_sha256 "${lrat_check_sha}" "${repo_root}/toolchain/lrat-check.c"
check_sha256 "${drat_license_sha}" "${repo_root}/toolchain/drat-trim-LICENSE"
check_sha256 "${cake_asm_sha}" \
  "${repo_root}/toolchain/cake_lpr/cake_lpr_arm8.S"
check_sha256 "${cake_ffi_sha}" \
  "${repo_root}/toolchain/cake_lpr/basis_ffi.c"
check_sha256 "${cake_license_sha}" \
  "${repo_root}/toolchain/cake_lpr/LICENSE"

cc -O2 -std=c99 -DLONGTYPE \
  "${repo_root}/toolchain/lrat-check.c" \
  -o "${build_root}/lrat-check"

if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
  cc -O2 -std=c99 \
    "${repo_root}/toolchain/cake_lpr/basis_ffi.c" \
    "${repo_root}/toolchain/cake_lpr/cake_lpr_arm8.S" \
    -o "${build_root}/cake_lpr"
fi

if [[ ! -d "${build_root}/drat-trim/.git" ]]; then
  git clone https://github.com/marijnheule/drat-trim.git \
    "${build_root}/drat-trim"
fi
git -C "${build_root}/drat-trim" fetch --quiet origin "${drat_commit}"
git -C "${build_root}/drat-trim" checkout --quiet "${drat_commit}"
make -C "${build_root}/drat-trim"

if [[ ! -d "${build_root}/cadical/.git" ]]; then
  git clone https://github.com/arminbiere/cadical.git \
    "${build_root}/cadical"
fi
git -C "${build_root}/cadical" fetch --quiet origin "${cadical_commit}"
git -C "${build_root}/cadical" checkout --quiet "${cadical_commit}"
(
  cd "${build_root}/cadical"
  ./configure
  make -C build
)

test "$("${build_root}/cadical/build/cadical" --version)" = "1.7.3"
test "$(git -C "${build_root}/drat-trim" rev-parse HEAD)" = "${drat_commit}"
test "$(git -C "${build_root}/cadical" rev-parse HEAD)" = "${cadical_commit}"

echo "TOOLCHAIN VERIFIED"
echo "lrat-check ${build_root}/lrat-check"
if [[ -x "${build_root}/cake_lpr" ]]; then
  echo "cake_lpr ${build_root}/cake_lpr"
else
  echo "cake_lpr not built (the vendored generated assembly targets Arm64)"
fi
echo "drat-trim ${build_root}/drat-trim/drat-trim"
echo "cadical ${build_root}/cadical/build/cadical"
