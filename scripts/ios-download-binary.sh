#!/usr/bin/env sh

PODS_TARGET_SRCROOT=iOS

set -euo pipefail
DTPROTOROOT="${PODS_TARGET_SRCROOT}/DTProto"
DTPROTOZIP="libuniffi_dtproto.a.zip"
if [ -e "${DTPROTOROOT}/libuniffi_dtproto.a" ]; then
 # exists
 exit 0
fi
cd "${DTPROTOROOT}"

curl -OL "https://github.com/TempTalkOrg/dtproto/releases/download/latest/libuniffi_dtproto.a.zip"

if [ -e "${DTPROTOZIP}" ]; then
 unzip "${DTPROTOZIP}"  -x '__MACOSX/*'
fi
if [ -e "${DTPROTOZIP}" ]; then
 rm "${DTPROTOZIP}"
fi