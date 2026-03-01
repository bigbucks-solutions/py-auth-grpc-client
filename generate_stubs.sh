#!/usr/bin/env bash
# Regenerate Python gRPC stubs from the proto file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="${SCRIPT_DIR}/proto"
OUT_DIR="${SCRIPT_DIR}/auth_grpc_client/generated"

mkdir -p "${OUT_DIR}"

python -m grpc_tools.protoc \
  -I"${PROTO_DIR}" \
  --python_out="${OUT_DIR}" \
  --grpc_python_out="${OUT_DIR}" \
  "${PROTO_DIR}/auth.proto"

# Fix imports to be relative within the package
sed -i '' 's/^import auth_pb2 as/from . import auth_pb2 as/' "${OUT_DIR}/auth_pb2_grpc.py"

echo "Stubs regenerated in ${OUT_DIR}"
