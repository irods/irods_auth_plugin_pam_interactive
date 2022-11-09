#! /bin/bash -xe

build_dir=/bld
source_dir=/src
cmake_path=/opt/irods-externals/cmake3.21.4-0/bin

mkdir -p ${build_dir} && cd ${build_dir}

PATH=${cmake_path}:$PATH

cmake ${source_dir}

make -j package
