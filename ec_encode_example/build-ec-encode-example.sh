#!/bin/bash
pwd=$(dirname "$(readlink -f "$0")")
prefix=${prefix:-"$pwd/install"}
arch=$(arch)
[[ $arch == "x86_64" ]] && gf_cfg_args="--enable-avx"

prefix=$(readlink -f "$prefix")

echo "This script prepares builds a tester application for erasure coding offload."
echo "The tester is part of storage verification system."
echo "It compares erasure coding offload versus software implementation (jerasure library)"
echo ""
echo "jerasure lib depends on gf-complete. Both libraries will be installed in $prefix/lib"
echo ""
echo "Building for $arch architecture"
echo "Prefix: ${prefix}"
echo ""

mkdir -p ${prefix}

if git submodule status ../gf-complete ../jerasure | grep -q '^-'; then
    echo "ERROR: required git submodules not found."
    echo "Update git submodules with 'git submodule update --init'"
    exit 1
fi

echo "Building gf-complete ..."
(cd ../gf-complete &&  ./autogen.sh && ./configure --prefix="$prefix" "$gf_cfg_args" && make -j install)

echo "Building jerasure ..."
(cd ../jerasure && autoreconf --force --install -I m4 && ./configure LDFLAGS="-L$prefix/lib" CPPFLAGS="-I$prefix/include" --prefix="$prefix" && make -j install)

echo "Building erasure coding tester ..."
CFLAGS="-I$prefix/include -I$prefix/include/jerasure" LIBRARY_PATH="$prefix/lib" make

echo ""
echo ""
echo "How to run:"
echo "   Provide a path to gf-complete and jerasure in command line using \$LD_LIBRARY_PATH."
echo "   Run /$pwd/ibv_ec_perf_sync --help to see command line parameters."
echo "   Don't forget to provide valid IB and network interfaces."
echo ""
LD_LIBRARY_PATH=$prefix/lib $pwd/ibv_ec_perf_sync --help

echo "Example:"
#echo "LD_LIBRARY_PATH=$prefix/lib PATH=\$PATH:$pwd/storage_verification/e2e_ver/vsa/scripts/ec_tests/  $pwd/storage_verification/e2e_ver/vsa/scripts/ec_tests/run_ec_perf_encode.sh -d mlx5_4 -i ib0 -k 10 -m 2 -w 8 -c 1 -b 1024,1024 -q 1 -l 512 -r 180"
echo "LD_LIBRARY_PATH=$prefix/lib $pwd/ibv_ec_perf_sync -r 16 -f 0 -i mlx5_4 -k 10 -m 2 -w 8 -s 10485760"
