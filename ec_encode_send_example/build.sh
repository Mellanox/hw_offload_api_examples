#!/bin/bash
pwd=$(dirname "$(readlink -f "$0")")
prefix=${prefix:-"$pwd/install"}
arch=$(arch)
gf_cfg_args=$(( $(arch) == "x86_64" ? "--enable-avx" : "" ))

prefix=$(readlink -f "$prefix")

echo "This script prepares builds a tester application for erasure coding offload."
echo "The tester is part of storage verification system."
echo "It compares erasure coding offload versus software implementation (jerasure library)"
echo ""
echo "jerasure lib depends on gf-complete. Both libraries will be installed in $prefix/lib"
echo ""
echo "Building for $arch architecture"
echo "Prefix: ${prefix}"

mkdir -p ${prefix}

if [ ! -d "../gf-complete" -o ! -d "../jerasure" ]; then
	echo "Update git submodules"
	echo "git submodule update --init"
	exit 1
fi

echo "Buildin gf-complete ..."
#if [[ $(arch) == "x86_64" ]]; then
#	set gf_cfg_args="--enable-avx"
#fi
#
(cd ../gf-complete &&  ./autogen.sh && ./configure --prefix="$prefix" "$gf_cfg_args" && make -j install)

echo "Building jerasure ..."
(cd ../jerasure && autoreconf --force --install -I m4 && ./configure LDFLAGS="-L$prefix/lib" CPPFLAGS="-I$prefix/include" --prefix="$prefix" && make -j install)

echo "Building erasure coding tester ..."
make -B JERASURE_INSTALL_DIR="$prefix"

echo ""
echo ""
echo "How to run:"
echo "   Provide a path to gf-complete and jerasure in command line using \$LD_LIBRARY_PATH."
echo "   Run /$pwd/ec_encode_send_perf --help to see command line parameters."
echo "   Don't forget to provide valid IB and network interfaces."
echo ""
LD_LIBRARY_PATH=$prefix/lib $pwd/ec_encode_send_perf --help

echo "Example:"
echo "LD_LIBRARY_PATH=$prefix/lib $pwd/ec_encode_send_perf -r 16 -f 0 -i mlx5_4 -k 10 -m 2 -w 8 -s 10485760"
