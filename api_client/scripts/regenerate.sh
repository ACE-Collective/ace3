#!/usr/bin/env bash
#
# regenerate the aceapi_v2_client package from the ACE API v2 openapi schema.
#
# this fetches the latest openapi.json from a running ACE instance, regenerates
# the generated portion of the package, and preserves the hand-maintained files
# (auth.py and py.typed). the generator is installed into a throwaway virtual
# environment so it never pollutes your main python environment.
#
# usage:
#   scripts/regenerate.sh [SCHEMA_URL]
#
# environment variables:
#   SCHEMA_URL   url of the openapi.json to fetch
#                (default: https://ace-http/api/v2/openapi.json)
#   CURL_OPTS    extra options passed to curl (default: -sk for self-signed tls)
#
# after running, review the diff (git diff aceapi_v2_client/), bump the version
# in pyproject.toml if the api changed, and rebuild (python -m build).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA_URL="${1:-${SCHEMA_URL:-https://ace-http/api/v2/openapi.json}}"
CURL_OPTS="${CURL_OPTS:--sk}"

PKG_DIR="${PROJECT_DIR}/aceapi_v2_client"
SCHEMA_FILE="${PROJECT_DIR}/openapi.json"
CONFIG_FILE="${PROJECT_DIR}/openapi-python-client-config.yaml"

# files we hand-maintain inside the package; these must survive regeneration
PRESERVE=(auth.py py.typed)

# the generator runs from a venv, so the work dir must be on an exec-capable
# filesystem. /tmp is often mounted noexec, so default to a project-local dir
# (override with REGEN_TMPDIR). it is removed on exit.
REGEN_TMPDIR="${REGEN_TMPDIR:-${PROJECT_DIR}/.regen}"
mkdir -p "${REGEN_TMPDIR}"
TMP_DIR="$(mktemp -d -p "${REGEN_TMPDIR}")"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

# ruff discovers its settings by walking up from the files it formats. because
# the staging dir lives inside the repo by default, any ruff.toml further up the
# tree would silently change the generated output. drop an empty config beside
# the staging dir so discovery stops here and the generator always formats with
# ruff's defaults.
: > "${TMP_DIR}/ruff.toml"

echo ">> fetching schema from ${SCHEMA_URL}"
# shellcheck disable=SC2086
curl ${CURL_OPTS} --fail -o "${SCHEMA_FILE}" "${SCHEMA_URL}"
python3 -m json.tool "${SCHEMA_FILE}" > /dev/null
echo ">> wrote $(wc -c < "${SCHEMA_FILE}") bytes to ${SCHEMA_FILE}"

echo ">> creating isolated venv for the generator"
python3 -m venv "${TMP_DIR}/venv"
"${TMP_DIR}/venv/bin/pip" install --quiet --upgrade pip
# pin to the same major/minor used to author this client
"${TMP_DIR}/venv/bin/pip" install --quiet "openapi-python-client>=0.29.0,<0.30.0"

echo ">> generating client into a staging directory"
# the generator shells out to `ruff` (installed as one of its dependencies) to
# lint and format its output. it looks for it on PATH, so the venv's bin dir has
# to be there -- calling the generator by absolute path alone is not enough, and
# silently yields unformatted, unsorted-import output.
PATH="${TMP_DIR}/venv/bin:${PATH}"
export PATH
"${TMP_DIR}/venv/bin/openapi-python-client" generate \
    --path "${SCHEMA_FILE}" \
    --meta none \
    --config "${CONFIG_FILE}" \
    --output-path "${TMP_DIR}/aceapi_v2_client"
rm -rf "${TMP_DIR}/aceapi_v2_client/.ruff_cache"

echo ">> stashing hand-maintained files"
STASH="${TMP_DIR}/stash"
mkdir -p "${STASH}"
for f in "${PRESERVE[@]}"; do
    if [ -e "${PKG_DIR}/${f}" ]; then
        cp "${PKG_DIR}/${f}" "${STASH}/${f}"
    fi
done

echo ">> replacing generated package contents"
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"
cp -r "${TMP_DIR}/aceapi_v2_client/." "${PKG_DIR}/"

echo ">> restoring hand-maintained files"
for f in "${PRESERVE[@]}"; do
    if [ -e "${STASH}/${f}" ]; then
        cp "${STASH}/${f}" "${PKG_DIR}/${f}"
    fi
done
# py.typed is a hand-added marker; ensure it exists even on a fresh checkout
touch "${PKG_DIR}/py.typed"

echo ""
echo ">> done. next steps:"
echo "   1. review changes:   git -C '${PROJECT_DIR}' diff aceapi_v2_client/"
echo "   2. if the api changed, bump 'version' in pyproject.toml and"
echo "      'package_version_override' in openapi-python-client-config.yaml"
echo "   3. rebuild:           (cd '${PROJECT_DIR}' && python -m build)"
