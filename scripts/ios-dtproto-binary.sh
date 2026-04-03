#!/usr/bin/env bash
set -e

TARGETNAME=uniffi_dtproto
SRCPATH=../src
iOSPATH=../iOS/DTProto
TARGETPATH=../target
MODULEMAPPATH=${SRCPATH}/dtprotoFFI.modulemap
IPHONEOSPATH=${iOSPATH}/${TARGETNAME}/iphoneos
SIMULATORPATH=${iOSPATH}/${TARGETNAME}/iphonesimulator

echo "start working."

echo "1. Generating swift ..."
cargo run --bin uniffi-bindgen generate ${SRCPATH}/dtproto.udl --language swift
echo "2. Generating x86_64.a ..."
cargo rustc -p ${TARGETNAME} --lib --crate-type staticlib --release --target x86_64-apple-ios
echo "3. Generating arm64.a ..."
cargo rustc -p ${TARGETNAME} --lib --crate-type staticlib --release --target aarch64-apple-ios
echo "4. Generating Simulator on ARM64 ..."
cargo rustc -p ${TARGETNAME} --lib --crate-type staticlib --release --target aarch64-apple-ios-sim
echo "5. Combining arm64-sim.a and x86_64.a ..."
lipo -create ${TARGETPATH}/aarch64-apple-ios-sim/release/lib${TARGETNAME}.a \
             ${TARGETPATH}/x86_64-apple-ios/release/lib${TARGETNAME}.a \
             -output ${iOSPATH}/lib${TARGETNAME}.a
echo "6. Building folders ..."
mkdir -p ${IPHONEOSPATH}
mkdir -p ${SIMULATORPATH}
mv ${TARGETPATH}/aarch64-apple-ios/release/lib${TARGETNAME}.a ${IPHONEOSPATH}
mv ${iOSPATH}/lib${TARGETNAME}.a ${SIMULATORPATH}

echo "7. moving source files."
mv ${SRCPATH}/*.h         ${iOSPATH}/dtprotoFFI
mv ${SRCPATH}/*.swift     ${iOSPATH}
if [ -f ${MODULEMAPPATH} ]; then
  rm ${MODULEMAPPATH}
fi

echo "congratulations 🎉"