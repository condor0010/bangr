#!/bin/bash
export BN_API_PATH=$(pwd)/binaryninjaapi/
export BN_INSTALL_DIR=/opt/binaryninja/
cmake -S . -B build
pushd build
make -j 4 install
popd
