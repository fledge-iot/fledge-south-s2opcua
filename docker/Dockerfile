# Fledge with the s2opcua south plugin built from this checkout.
#
# Used by ../docker-compose.yml; the build context is the repository root.
#
# Stage "builder" compiles the S2OPC Toolkit and its dependencies with the repository's
# requirements.sh, then builds the plugin against the Fledge headers of the matching release.
# Stage "runtime" is Fledge installed from the Fledge apt repository plus the built plugin.

ARG BASE_IMAGE=ubuntu:22.04

##### Stage: builder
FROM ${BASE_IMAGE} AS builder

ARG FLEDGE_VERSION=3.1.1
ARG FLEDGE_CODENAME=jammy
ARG APT_REPO_URL=https://packages.helinplatform.com/apt

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo ca-certificates curl wget git dos2unix patch gnupg \
        build-essential cmake g++ make autoconf automake libtool pkg-config \
        python3 uuid-dev libssl-dev libcurl4-openssl-dev \
        libboost-dev libboost-system-dev libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

# Fledge core libraries (for linking) from the Fledge apt repository.
# The package is unpacked rather than installed so its postinst does not run in the build stage.
RUN curl -fsSL "${APT_REPO_URL}/fledge.gpg" -o /usr/share/keyrings/fledge.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/fledge.gpg] ${APT_REPO_URL} ${FLEDGE_CODENAME} main" \
        > /etc/apt/sources.list.d/fledge.list \
    && apt-get update \
    && cd /tmp && apt-get download "fledge=${FLEDGE_VERSION}" \
    && dpkg-deb -x /tmp/fledge_*.deb / \
    && rm -f /tmp/fledge_*.deb && rm -rf /var/lib/apt/lists/*

# Fledge headers from the source tree of the same release.
# FindFledge.cmake expects the libraries in <source>/cmake_build/C/lib.
RUN git clone --depth 1 --branch "v${FLEDGE_VERSION}" https://github.com/fledge-iot/fledge.git /build/fledge \
    && mkdir -p /build/fledge/cmake_build/C \
    && ln -s /usr/local/fledge/lib /build/fledge/cmake_build/C/lib

# S2OPC Toolkit, mbedtls, libexpat and libcheck. Copied on their own so that this slow
# step is cached and only re-runs when requirements.sh changes.
WORKDIR /build/deps
COPY requirements.sh check-0.15.2_CMakeLists.txt.patch ./
RUN dos2unix -q requirements.sh check-0.15.2_CMakeLists.txt.patch \
    && bash ./requirements.sh

# The plugin. Windows checkouts may have CRLF line endings, which break the mkversion script.
COPY . /build/plugin
WORKDIR /build/plugin
RUN find . -type f -not -path './.git/*' -print0 | xargs -0 -r dos2unix -q 2>/dev/null || true \
    && chmod +x mkversion \
    && rm -rf build && mkdir build && cd build \
    && cmake -DFLEDGE_SRC=/build/fledge -DFLEDGE_INSTALL=/usr/local/fledge .. \
    && make -j"$(nproc)" \
    && make install

# Collect what the runtime image needs: the plugin, the shared libraries it loads,
# and the container support files from the Fledge release.
RUN mkdir -p /out/plugin /out/lib /out/image \
    && cp -a /usr/local/fledge/plugins/south/s2opcua/. /out/plugin/ \
    && cp -a /usr/local/lib/libs2opc_*.so* /usr/local/lib/libexpat.so* /out/lib/ \
    && cp /build/fledge/.ci/image/entrypoint.sh /build/fledge/.ci/image/rsyslog.conf \
          /build/fledge/.ci/image/rsyslog-rotate.sh /out/image/ \
    && dos2unix -q /out/image/*

##### Stage: runtime
FROM ${BASE_IMAGE} AS runtime

ARG FLEDGE_VERSION=3.1.1
ARG FLEDGE_CODENAME=jammy
ARG APT_REPO_URL=https://packages.helinplatform.com/apt

ENV DEBIAN_FRONTEND=noninteractive \
    FLEDGE_ROOT=/usr/local/fledge \
    FLEDGE_DATA=/usr/local/fledge/data \
    FLEDGE_STORAGE_GRACE=90 \
    PATH=/usr/local/fledge/bin:$PATH \
    PYTHONPATH=/usr/local/fledge/python \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# The Fledge package postinst calls systemctl, which does not exist in a container.
RUN printf '%s\n' '#!/bin/sh' 'echo "[systemctl stub] $*" >&2' 'exit 0' > /usr/bin/systemctl \
    && chmod +x /usr/bin/systemctl

# build-essential and python3-dev are only needed by the Fledge postinst pip install.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg procps rsyslog build-essential python3-dev \
    && curl -fsSL "${APT_REPO_URL}/fledge.gpg" -o /usr/share/keyrings/fledge.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/fledge.gpg] ${APT_REPO_URL} ${FLEDGE_CODENAME} main" \
        > /etc/apt/sources.list.d/fledge.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends "fledge=${FLEDGE_VERSION}" \
    && apt-get purge -y --auto-remove build-essential python3-dev \
    && rm -rf /root/.cache/pip /var/lib/apt/lists/*

COPY --from=builder /out/lib/ /usr/local/lib/
COPY --from=builder /out/plugin/ /usr/local/fledge/plugins/south/s2opcua/
COPY --from=builder /out/image/rsyslog.conf /etc/rsyslog.conf
COPY --from=builder /out/image/rsyslog-rotate.sh /usr/local/bin/fledge-log-rotate
COPY --from=builder /out/image/entrypoint.sh /usr/local/bin/fledge-entrypoint

# Fail the build if the plugin cannot resolve all of its shared libraries.
RUN chmod +x /usr/local/bin/fledge-log-rotate /usr/local/bin/fledge-entrypoint \
    && ldconfig \
    && LD_LIBRARY_PATH=/usr/local/fledge/lib ldd /usr/local/fledge/plugins/south/s2opcua/libs2opcua.so \
        | tee /dev/stderr | (! grep -q "not found")

EXPOSE 8081
VOLUME ["/usr/local/fledge/data"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=6 \
  CMD curl -fsS http://localhost:8081/fledge/ping || exit 1

ENTRYPOINT ["/usr/local/bin/fledge-entrypoint"]
