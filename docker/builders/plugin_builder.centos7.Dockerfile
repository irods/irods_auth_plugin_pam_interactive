# syntax=docker/dockerfile:1.5

FROM centos:7

SHELL [ "/usr/bin/bash", "-c" ]

# Make sure we're starting with an up-to-date image
RUN --mount=type=cache,target=/var/cache/yum,sharing=locked \
    yum update -y || [ "$?" -eq 100 ] && \
    rm -rf /tmp/*

RUN --mount=type=cache,target=/var/cache/yum,sharing=locked \
    yum install -y \
        centos-release-scl \
        epel-release \
        gcc-c++ \
        make \
        rpm-build \
        sudo \
        wget \
    && \
    rm -rf /tmp/*

RUN rpm --import https://packages.irods.org/irods-signing-key.asc && \
    wget -qO - https://packages.irods.org/renci-irods.yum.repo | tee /etc/yum.repos.d/renci-irods.yum.repo && \
    rpm --import https://core-dev.irods.org/irods-core-dev-signing-key.asc && \
    wget -qO - https://core-dev.irods.org/renci-irods-core-dev.yum.repo | tee /etc/yum.repos.d/renci-irods-core-dev.yum.repo && \
    yum check-update -y || { rc=$?; [ "$rc" -eq 100 ] && exit 0; exit "$rc"; } && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*

RUN --mount=type=cache,target=/var/cache/yum,sharing=locked \
    yum install -y \
        irods-devel \
        irods-externals-clang13.0.0-0 \
        irods-externals-cmake3.21.4-0 \
        pam-devel \
    && \
    rm -rf /tmp/*

ENV file_extension="rpm"
ENV package_manager="yum"

COPY --chmod=755 build_packages.sh /
ENTRYPOINT ["./build_packages.sh"]
