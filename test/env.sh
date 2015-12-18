#!/bin/sh

CURDIR=`pwd`

export LD_LIBRARY_PATH=${CURDIR}/lib:${CURDIR}/../out/lib:${LD_LIBRARY_PATH}

