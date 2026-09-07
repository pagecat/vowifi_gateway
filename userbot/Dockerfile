# Telegram userbot sidecar: ntgcalls (Telegram WebRTC) + PJSUA2 (SIP).
#
# Separate from the control plane on purpose. It carries two native stacks and a
# Telegram session that is equivalent to a user account; keeping that out of the
# manager process means a crash here cannot take the gateway with it.
#
# Build (from the repo root):  docker build -f userbot/Dockerfile -t vowifi/userbot .
#
# ntgcalls ships prebuilt wheels for linux x86_64 and arm64, so only PJSIP is
# compiled here. That build is the slow part on a Pi — expect a long first build.
FROM python:3.12-slim

ARG PJSIP_VERSION=2.14.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential swig python3-dev pkg-config \
        libasound2-dev libssl-dev libopus-dev \
        wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# PJSIP 2.14.1's SWIG setup.py still does `from distutils.core import setup`.
# Python 3.12 removed distutils; setuptools<81 puts it back.
RUN pip install --no-cache-dir 'setuptools<81'

# PJSIP with the Python bindings. --disable-sound is deliberate: the container
# has no audio hardware and must not look for any; all audio moves through the
# bridge port in sip_leg.py. Opus stays enabled so a wideband local leg is
# possible later, even though the IMS trunk is narrowband AMR today.
RUN cd /tmp \
    && wget -qO pjproject.tar.gz "https://github.com/pjsip/pjproject/archive/refs/tags/${PJSIP_VERSION}.tar.gz" \
    && tar xf pjproject.tar.gz && cd "pjproject-${PJSIP_VERSION}" \
    && ./configure --enable-shared --disable-sound --disable-video \
                   --disable-v4l2 --disable-sdl --disable-ffmpeg \
                   --with-external-srtp=no CFLAGS="-fPIC -O2" \
    && make dep && make -j"$(nproc)" && make install && ldconfig \
    && cd pjsip-apps/src/swig/python \
    && make && make install \
    && cd /tmp && rm -rf "pjproject-${PJSIP_VERSION}" pjproject.tar.gz

WORKDIR /app
COPY userbot/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY userbot/*.py ./

# The session file IS the account — it belongs on the mounted data volume, never
# in the image. config.json is mounted alongside it.
VOLUME ["/data/userbot"]
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
