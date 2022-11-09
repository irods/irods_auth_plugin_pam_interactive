FROM ubuntu:20.04

SHELL [ "/bin/bash", "-c" ]

ENV DEBIAN_FRONTEND=noninteractive

# Make sure we're starting with an up-to-date image
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y --purge && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*
# To mark all installed packages as manually installed:
#apt-mark showauto | xargs -r apt-mark manual

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        apt-utils \
        build-essential \
        git \
        gnupg \
        libxml2-dev \
        lsb-release \
        python3 \
        python3-distro \
        python3-pip \
        python3-setuptools \
        sudo \
        wget \
    && \
    pip --no-cache-dir install --upgrade 'pip<21.0' && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

ENV python="python3"

RUN wget -qO - https://packages.irods.org/irods-signing-key.asc | apt-key add - && \
    echo "deb [arch=amd64] https://packages.irods.org/apt/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/renci-irods.list && \
    apt-get update

RUN apt install -y 'irods-externals*' irods-dev libpam-dev 

COPY build_packages.sh /
RUN chmod u+x /build_packages.sh
ENTRYPOINT ["./build_packages.sh"]
