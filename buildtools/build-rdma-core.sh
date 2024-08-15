#!/bin/bash

build_rdma_core() {
    # Skip if ./build/rdma-core exists
    if [[ -d build/rdma-core ]]; then
        echo ":: rdma-core is already built" && return
    fi

    mkdir -p build
    pushd build
	git clone https://github.com/linux-rdma/rdma-core.git
    cd rdma-core
    git checkout tags/v53.0 -b v53.0
    mkdir -p build
    cd build
    CFLAGS=-fPIC cmake -DIN_PLACE=1 -DENABLE_STATIC=1 -GNinja ..
    ninja
    popd
}

build_rdma_core