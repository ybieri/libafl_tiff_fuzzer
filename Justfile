#  RUST_LOG=debug env ARCH=aarch64 LIBAFL_FUZZBENCH_DEBUG=1 RUST_BACKTRACE=1 just single_dev 

# Variables from libafl.just
PROFILE := env("PROFILE", "release")
FUZZER_EXTENSION := if os_family() == "windows" { ".exe" } else { "" }
PROFILE_DIR := if PROFILE == "dev" { "debug" } else { "release" }
TARGET_DIR := absolute_path(env("TARGET_DIR", "target"))
BUILD_DIR := TARGET_DIR / PROFILE_DIR

# Variables from libafl-qemu.just
ARCH := env("ARCH", "x86_64")
DOTENV := source_directory() / "envs" / ".env." + ARCH

FUZZER_NAME := "qemu_launcher"
FUZZER := BUILD_DIR / FUZZER_NAME + FUZZER_EXTENSION

# Determine target triple based on ARCH
TARGET_TRIPLE := if ARCH == "aarch64" { "aarch64-unknown-linux-gnu" } else if ARCH == "x86_64" { "x86_64-unknown-linux-gnu" } else { "x86_64-unknown-linux-gnu" }
HOST_TRIPLE := "x86_64-unknown-linux-gnu"
CROSS_CC := if ARCH == "aarch64" { "aarch64-linux-gnu-gcc" } else { "gcc" }
CROSS_PREFIX := if ARCH == "aarch64" { "aarch64-linux-gnu-" } else { "" }

HARNESS := TARGET_DIR / "build" / "bin" / "tiffinfo"

DEPS_DIR := TARGET_DIR / "deps"
TIFF_DIR := source_directory() / "tiff"
BUILD_DIR_TIFF := TARGET_DIR / "build"
ROOTFS_DIR := TARGET_DIR / "rootfs"
STATIC_BUILD := env("STATIC", "no")

[unix]
target_dir:
    mkdir -p {{ TARGET_DIR }}

[unix]
deps_dir:
    mkdir -p {{ DEPS_DIR }}

[unix]
build_dir_tiff:
    mkdir -p {{ BUILD_DIR_TIFF }}

[unix]
build:
    #!/bin/bash
    # Export CROSS_CC for libafl_qemu build script when cross-compiling
    if [ "{{ ARCH }}" == "aarch64" ]; then
        export CROSS_CC=aarch64-linux-gnu-gcc
    fi
    cargo build \
      --profile {{ PROFILE }} \
      --features {{ ARCH }} \
      --target-dir {{ TARGET_DIR }}

[unix]
download_tiff:
    #!/bin/bash
    TIFF_DIR={{ source_directory() }}/tiff
    if [ ! -d "$TIFF_DIR" ]; then
        echo "Downloading tiff source..."
        cd {{ source_directory() }} && \
        wget http://download.osgeo.org/libtiff/tiff-4.0.6.tar.gz && \
        tar xf tiff-4.0.6.tar.gz && \
        mv tiff-4.0.6 tiff && \
        rm tiff-4.0.6.tar.gz
    else
        echo "tiff directory already exists"
    fi


[unix]
tiffinfo: download_tiff build_dir_tiff
    #!/bin/bash

    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true

    # Clean old build artifacts
    cd {{ TIFF_DIR }} && \
        rm -f Makefile config.log config.status libtool && \
        find . -name "*.o" -delete && \
        find . -name "*.lo" -delete && \
        find . -type d -name ".libs" -exec rm -rf {} + 2>/dev/null; true

    STATIC_FLAGS=""
    if [ "{{ STATIC_BUILD }}" == "yes" ]; then
        STATIC_FLAGS="--enable-static --disable-shared LDFLAGS=-static"
    fi

    cd {{ TIFF_DIR }} && \
        export CC={{ CROSS_CC }} && \
        export CXX={{ CROSS_PREFIX }}g++ && \
        export AR={{ CROSS_PREFIX }}ar && \
        export RANLIB={{ CROSS_PREFIX }}ranlib && \
        export LD={{ CROSS_PREFIX }}ld && \
        export STRIP={{ CROSS_PREFIX }}strip && \
        ./configure \
            --prefix="{{ BUILD_DIR_TIFF }}" \
            --target={{ TARGET_TRIPLE }} \
            --host={{ HOST_TRIPLE }} \
            --disable-cxx \
            $STATIC_FLAGS && \
        make -C {{ TIFF_DIR }} -j && \
        make -C {{ TIFF_DIR }} install
    
     # Create corpus directory with test images
    if [ ! -d "corpus" ]; then
        mkdir -p corpus
        if [ -d "{{ TIFF_DIR }}/test/images" ]; then
            cp {{ TIFF_DIR }}/test/images/*.tiff corpus/ 2>/dev/null || true
        fi
    fi

[unix]
harness: tiffinfo
    # harness stuff 
    @echo "tiffinfo binary ready at {{ HARNESS }}"

[unix]
run: harness build
    #!/bin/bash
    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_host.so \
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{TARGET_DIR}}/output/log.txt \
        --cores 0-7 \
        --asan-host-cores 0-1 \
        --cmplog-cores 2-3 \
        --tui \
        -- \
        {{ HARNESS }} -Dcjrsw infile

[unix]
run_snapshots: harness build
    #!/bin/bash
    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_host.so \
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{TARGET_DIR}}/output/log.txt \
        --cores 0-7 \
        --asan-host-cores 0-1 \
        --cmplog-cores 2-3 \
        --snapshots \
        --tui \
        -- \
        {{ HARNESS }} -Dcjrsw infile

[unix]
run_snapshots_debug: harness build
    #!/bin/bash
    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    export RUST_LOG=debug
    export RUST_BACKTRACE=1
    # Enable LibAFL snapshot debug output
    export LIBAFL_DEBUG_OUTPUT=1
    CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_host.so \
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{TARGET_DIR}}/output/log_debug.txt \
        --cores 0 \
        --snapshots \
        -- \
        {{ HARNESS }} -Dcjrsw infile 2>&1 | tee {{TARGET_DIR}}/output/debug.log


single_dev_gdb: harness build
    #!/bin/bash
    export PROFILE=dev
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    export RUST_BACKTRACE=1
    export RUST_LOG=debug
    cargo build \
      --profile dev \
      --features "simplemgr,{{ ARCH }}" \
      --target-dir {{ TARGET_DIR }}
    pwndbg --args {{ TARGET_DIR }}/debug/qemu_launcher \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        --snapshots \
        -- \
        {{ HARNESS }} -Dcjrsw infile 2>&1 | tee {{ TARGET_DIR }}/output/debug.log


single_dev_strace: harness build
    #!/bin/bash
    export PROFILE=dev
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    export RUST_BACKTRACE=1
    export RUST_LOG=${RUST_LOG:-debug}
    cargo build \
      --profile dev \
      --features "simplemgr,{{ ARCH }}" \
      --target-dir {{ TARGET_DIR }}
    strace -tt -yy -y -f -e trace=openat,open,read,write,pipe,socket,dup2,clone,close -s 10000 -o ./strace.log \
     {{ TARGET_DIR }}/debug/qemu_launcher \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        --snapshots \
        -- \
        {{ HARNESS }} -Dcjrsw infile


[unix]
test_inner: harness build
    #!/bin/bash

    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true

    export QEMU_LAUNCHER={{ FUZZER }}

    # Skip injection tests if they don't exist
    if [ -f "./tests/injection/test.sh" ]; then
        ./tests/injection/test.sh || exit 1
    fi

    # complie again with simple mgr
    cargo build --profile={{PROFILE}} --features="simplemgr,{{ARCH}}" --target-dir={{ TARGET_DIR }} || exit 1

    if [ -f "./tests/asan/host_test.sh" ]; then
        export CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_host.so
        ./tests/asan/host_test.sh || exit 1
    fi

    if [ -f "./tests/asan/guest_test.sh" ]; then
        export CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_guest.so
        ./tests/asan/guest_test.sh || exit 1
    fi

[unix]
test:
    ARCH=x86_64 just test_inner

single: harness build
    #!/bin/bash
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        -- \
        {{ HARNESS }} -Dcjrsw infile


single_dev:
    #!/bin/bash
    export PROFILE=dev
    export ROOTFS_PATH={{ TARGET_DIR }}/rootfs
    export LIBTIFF_PATH={{ TARGET_DIR }}/build/lib
    export QEMU_LD_PREFIX={{ TARGET_DIR }}/rootfs
    # Enable Rust backtraces for better crash debugging
    export RUST_BACKTRACE=1
    # Optional: Enable debugging (uncomment to use)
    # export LIBAFL_DEBUG_OUTPUT=1
    # export RUST_LOG=${RUST_LOG:-debug}
    cargo build \
      --profile dev \
      --features "simplemgr,{{ ARCH }}" \
      --target-dir {{ TARGET_DIR }}
     {{ TARGET_DIR }}/debug/qemu_launcher \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        --snapshots \
        -- \
        {{ HARNESS }} -Dcjrsw infile





asan_host: harness build
    #!/bin/bash

    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true
    CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_host.so \
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        --asan-host-cores 0 \
        -- \
        {{ HARNESS }} -Dcjrsw infile

asan_guest: harness build
    #!/bin/bash

    [ -f {{ DOTENV }} ] && source {{ DOTENV }} || true
    CUSTOM_LIBAFL_QEMU_ASAN_PATH={{ BUILD_DIR }}/$CROSS_TARGET/{{ PROFILE_DIR }}/libafl_qemu_asan_guest.so \
    {{ FUZZER }} \
        --input ./corpus \
        --output {{ TARGET_DIR }}/output/ \
        --log {{ TARGET_DIR }}/output/log.txt \
        --cores 0 \
        --asan-guest-cores 0 \
        -- \
        {{ HARNESS }} -Dcjrsw infile

[unix]
rootfs:
    #!/bin/bash
    # Create a minimal rootfs for aarch64 using debootstrap with Ubuntu Noble (24.04)
    # Use --foreign to skip chroot verification (we can't run arm64 binaries on x86_64)
    # for testing: QEMU_LD_PREFIX=target/rootfs LD_LIBRARY_PATH=target/build/lib qemu-aarch64-static target/build/bin/tiffinfo --version 
    
    if [ ! -d "{{ ROOTFS_DIR }}" ]; then
        sudo debootstrap \
            --arch=arm64 \
            --foreign \
            noble \
            {{ ROOTFS_DIR }} \
            http://ports.ubuntu.com/ubuntu-ports
        
        # Copy dynamic linker so QEMU can find it
        # QEMU expects /lib/ld-linux-aarch64.so.1 but debootstrap puts it in /usr/lib/aarch64-linux-gnu/
        sudo mkdir -p {{ ROOTFS_DIR }}/lib
        if [ -f "{{ ROOTFS_DIR }}/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ]; then
            sudo rm {{ ROOTFS_DIR }}/lib/ld-linux-aarch64.so.1
            sudo cp -fL {{ ROOTFS_DIR }}/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 {{ ROOTFS_DIR }}/lib/ld-linux-aarch64.so.1
        fi
    else
        echo "Rootfs already exists at {{ ROOTFS_DIR }}"
        # Ensure copy exists even if rootfs already exists
        if [ ! -f "{{ ROOTFS_DIR }}/lib/ld-linux-aarch64.so.1" ] && [ -f "{{ ROOTFS_DIR }}/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ]; then
            sudo mkdir -p {{ ROOTFS_DIR }}/lib
            sudo rm {{ ROOTFS_DIR }}/lib/ld-linux-aarch64.so.1
            sudo cp -fL {{ ROOTFS_DIR }}/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 {{ ROOTFS_DIR }}/lib/ld-linux-aarch64.so.1
        fi
    fi

[unix]
clean:
    cargo clean
    rm -rf {{ BUILD_DIR_TIFF }}
    rm -rf {{ TARGET_DIR }}/output
