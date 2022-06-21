FROM centos:7

SHELL [ "/usr/bin/bash", "-c" ]

# Make sure we're starting with an up-to-date image
RUN yum update -y || [ "$?" -eq 100 ] && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*

RUN yum install -y \
        epel-release \
        sudo \
        wget \
        git \
        rpm-build \
        gcc-c++ \
    && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*

# python 2 and 3 must be installed separately because yum will ignore/discard python2
RUN yum install -y \
        python3 \
        python3-devel \
        python3-pip \
    && \
    yum install -y \
        python \
        python-devel \
        python-pip \
    && \
    pip --no-cache-dir install --upgrade 'pip<21.0' && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*

ENV python="python3"

RUN rpm --import https://packages.irods.org/irods-signing-key.asc && \
    wget -qO - https://packages.irods.org/renci-irods.yum.repo | tee /etc/yum.repos.d/renci-irods.yum.repo && \
    rpm --import https://core-dev.irods.org/irods-core-dev-signing-key.asc && \
    wget -qO - https://core-dev.irods.org/renci-irods-core-dev.yum.repo | tee /etc/yum.repos.d/renci-irods-core-dev.yum.repo && \
    yum check-update -y || { rc=$?; [ "$rc" -eq 100 ] && exit 0; exit "$rc"; } && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*

RUN yum install -y irods-devel 'irods-externals*' pam-devel && \
    yum clean all && \
    rm -rf /var/cache/yum /tmp/*
