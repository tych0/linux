#!/bin/bash -eux

arch=${1:-}
target=${2:-}

function do_build()
{
    [ -d ${O} ] || mkdir ${O}

    rm -f ${O}/.version
    cp -f ${CONFIG} ${O}/.config

    export ARCH CROSS_COMPILE
    make -j8 O=${O} ${TARGET}

    cp -f ${O}/.config ${CONFIG}
}

if [ -z "${arch}" -o "${arch}" = "arm64" ] ; then
    CONFIG="config-xpfo-arm64"
    O="build-arm64"
    ARCH="arm64"
    CROSS_COMPILE="aarch64-linux-gnu-"
    TARGET="${target:-bindeb-pkg}"

    do_build
fi

if [ -z "${arch}" -o "${arch}" = "amd64" ] ; then
    CONFIG="config-xpfo-amd64"
    O="build-amd64"
    ARCH="x86"
    CROSS_COMPILE=
    TARGET="${target:-bindeb-pkg}"

    do_build
fi
