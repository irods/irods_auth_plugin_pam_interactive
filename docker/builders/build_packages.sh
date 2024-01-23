#! /bin/bash -e

usage() {
cat <<_EOF_
Available options:

    --irods-packages    Path to custom iRODS packages received via volume mount
    -h, --help          This message
_EOF_
    exit
}

build_dir=/bld
source_dir=/src
cmake_path=/opt/irods-externals/cmake3.21.4-0/bin
irods_packages_dir=

while [ -n "$1" ] ; do
    case "$1" in
        --irods-packages)        shift; irods_packages_dir="$1";;
        -h|--help)               usage;;
    esac
    shift
done

if [[ ! -z "${irods_packages_dir}" ]] ; then
    if [ "${package_manager}" == "apt-get" ] ; then
        apt-get update
        dpkg -i "${irods_packages_dir}"/irods-dev*."${file_extension}"
        dpkg -i "${irods_packages_dir}"/irods-runtime*."${file_extension}"
        apt-get install -fy --allow-downgrades
    elif [ "${package_manager}" == "yum" ] ; then
        rpm -i --force "${irods_packages_dir}"/irods-dev*."${file_extension}" "${irods_packages_dir}"/irods-runtime*."${file_extension}"
    elif [ "${package_manager}" == "dnf" ] ; then
        rpm -i --force "${irods_packages_dir}"/irods-dev*."${file_extension}" "${irods_packages_dir}"/irods-runtime*."${file_extension}"
    fi
fi

mkdir -p ${build_dir} && cd ${build_dir}

PATH=${cmake_path}:$PATH

cmake ${source_dir}

make -j package
