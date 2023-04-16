#!/bin/bash

if [[ "$1" == "debug" ]]; then
    BUILD_FLAG="BUILD_DEBUG=1"
elif [[ "$1" == "release" ]]; then
    BUILD_FLAG="BUILD_RELEASE=1"
elif [[ "$1" == "dev" ]]; then
    BUILD_FLAG="BUILD_DEV=1"
else
    echo "Error: First argument must be 'debug', 'release' or 'dev'"
    exit 1
fi

make $BUILD_FLAG

if [[ "$1" == "release" ]]; then
    strip vroutesrv
    strip vrouteclt
    strip libvroute_client.so
    strip libvroute_server.so
fi
