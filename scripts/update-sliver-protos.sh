#!/usr/bin/env bash
# Download Sliver protobuf definitions and compile Python gRPC stubs.
#
# Downloads .proto files from BishopFox/sliver master branch and compiles
# them into tools/sliver-server/proto_gen/ using grpc_tools.protoc.
#
# Usage:
#   scripts/update-sliver-protos.sh
#
# Prerequisites:
#   - uv (for running grpc_tools.protoc with project dependencies)
#   - curl
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SLIVER_SERVER_DIR="${REPO_DIR}/tools/sliver-server"
PROTO_DIR="${SLIVER_SERVER_DIR}/proto"
PROTO_GEN_DIR="${SLIVER_SERVER_DIR}/proto_gen"
SLIVER_BRANCH="master"
SLIVER_RAW="https://raw.githubusercontent.com/BishopFox/sliver/${SLIVER_BRANCH}/protobuf"

# Check prerequisites
if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required but not found."
    exit 1
fi

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found. Install from https://docs.astral.sh/uv/"
    exit 1
fi

# Create directories
mkdir -p "${PROTO_DIR}/commonpb" \
         "${PROTO_DIR}/sliverpb" \
         "${PROTO_DIR}/clientpb" \
         "${PROTO_DIR}/rpcpb"
mkdir -p "${PROTO_GEN_DIR}"

echo "Downloading Sliver protobuf files from ${SLIVER_BRANCH} branch..."

download_proto() {
    local subdir="$1" file="$2"
    local url="${SLIVER_RAW}/${subdir}/${file}"
    local dest="${PROTO_DIR}/${subdir}/${file}"
    echo "  ${subdir}/${file}"
    if ! curl -sL --fail "${url}" -o "${dest}"; then
        echo "ERROR: Failed to download ${url}"
        exit 1
    fi
}

download_proto "commonpb" "common.proto"
download_proto "sliverpb" "sliver.proto"
download_proto "clientpb" "client.proto"
download_proto "rpcpb" "services.proto"

echo ""
echo "Compiling protobuf stubs..."

# Ensure dependencies are installed
uv sync --directory "${SLIVER_SERVER_DIR}" --quiet

# Compile protos — output flat into proto_gen with package subdirectories
uv run --directory "${SLIVER_SERVER_DIR}" python -m grpc_tools.protoc \
    --proto_path="${PROTO_DIR}" \
    --python_out="${PROTO_GEN_DIR}" \
    --pyi_out="${PROTO_GEN_DIR}" \
    --grpc_python_out="${PROTO_GEN_DIR}" \
    "commonpb/common.proto" \
    "sliverpb/sliver.proto" \
    "clientpb/client.proto" \
    "rpcpb/services.proto"

# Create __init__.py files for Python package structure
touch "${PROTO_GEN_DIR}/__init__.py"
for subdir in commonpb sliverpb clientpb rpcpb; do
    if [ -d "${PROTO_GEN_DIR}/${subdir}" ]; then
        touch "${PROTO_GEN_DIR}/${subdir}/__init__.py"
    fi
done

# Fix absolute imports in generated files.
# protoc generates imports like:
#   from commonpb import common_pb2
# We need:
#   from proto_gen.commonpb import common_pb2
# This is necessary because proto_gen is a subpackage, not a top-level package.
echo "Fixing imports in generated files..."
fix_imports() {
    local file="$1"
    if [ -f "$file" ]; then
        # Replace bare package imports with proto_gen-prefixed imports
        sed -i \
            -e 's/^from commonpb import/from proto_gen.commonpb import/g' \
            -e 's/^from sliverpb import/from proto_gen.sliverpb import/g' \
            -e 's/^from clientpb import/from proto_gen.clientpb import/g' \
            -e 's/^from rpcpb import/from proto_gen.rpcpb import/g' \
            -e 's/^import commonpb\./import proto_gen.commonpb./g' \
            -e 's/^import sliverpb\./import proto_gen.sliverpb./g' \
            -e 's/^import clientpb\./import proto_gen.clientpb./g' \
            -e 's/^import rpcpb\./import proto_gen.rpcpb./g' \
            "$file"
    fi
}

# Fix all generated Python files
find "${PROTO_GEN_DIR}" -name "*.py" -type f | while read -r pyfile; do
    fix_imports "$pyfile"
done

echo ""
echo "Done. Proto stubs compiled to ${PROTO_GEN_DIR}/"
echo ""
echo "Packages:"
for subdir in commonpb sliverpb clientpb rpcpb; do
    count=$(find "${PROTO_GEN_DIR}/${subdir}" -name "*.py" -not -name "__init__.py" 2>/dev/null | wc -l)
    echo "  ${subdir}: ${count} files"
done
