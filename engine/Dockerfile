# VoWiFi engine image: patched strongSwan-epdg + sysmocom Asterisk + USIM bridge.
# Based on phcoder/asterisk-docker (osmocom "VoWiFi with Asterisk"), with additions:
#   - pin_keeper.py : holds SIM PIN (CHV1) verified so IKE EAP-AKA + SIP IMS-AKA work on PIN-enabled SIMs
#   - ami_usim.py   : reference USIM<->AMI bridge, patched to VERIFY PIN + report status
#   - render.py     : renders /config/instance.json -> Asterisk/strongSwan configs at container start
# No strongSwan C source patch is needed for PIN (verification persists across PC/SC connections).
#
# Reproducibility: all build inputs are pinned so a from-scratch build on any machine/arch
# (amd64/arm64) is functionally identical — the base image tag below, sysmocom asterisk
# (sysmocom/20.7.0) + pjproject (sysmocom/2.14) + cherry-pick f1b60dc, patches/asterisk/*.py,
# and strongSwan-epdg (jolly/work). Pin the base tag rather than :latest for determinism.
# NOTE: Fedora 41 breaks strongSwan-epdg build; use 40 (last known-good).
FROM fedora:40

# pcsc-lite is pinned to a fixed upstream version and built from source (see below), so the
# engine's PC/SC client library matches the host pcscd EXACTLY across any distro — this is the
# same PCSC_VERSION the installer pins on the host and the control image uses. Avoids the
# client/server protocol mismatch that distro-default pcsc-lite packages cause.
ARG PCSC_VERSION=2.3.3

WORKDIR /home/asterisk-build
COPY patches/strongswan/01_configure_gettext.patch /home/asterisk-build/01_configure_gettext.patch
COPY patches/strongswan/02_warnings.patch /home/asterisk-build/02_warnings.patch
COPY patches/strongswan/03_eap_sim_pcsc_verify_pin.patch /home/asterisk-build/03_eap_sim_pcsc_verify_pin.patch

RUN dnf -y update && \
    dnf -y install git gcc g++ openssl-devel patch libedit-devel opus-devel libuuid-devel autoconf \
    automake libtool gettext perl python3 flex bison pkg-config m4 gettext-devel gperf gmp-devel \
    jansson-devel libxml2-devel sqlite-devel opencore-amr-devel vo-amrwbenc-devel \
    libmnl-devel speex-devel speexdsp-devel libvorbis-devel alsa-lib-devel portaudio-devel \
    libcurl-devel xmlstarlet postgresql-devel unixODBC-devel neon-devel gmime-devel lua-devel \
    uriparser-devel libxslt-devel mysql-devel bluez-libs-devel radcli-devel freetds-devel \
    jack-audio-connection-kit-devel libcap-devel net-snmp-devel corosynclib-devel newt-devel \
    popt-devel libical-devel spandsp-devel openldap-devel codec2-devel fftw-devel libsndfile-devel \
    unbound-devel wget subversion libresample-devel binutils-devel libsrtp-devel gsm-devel iproute \
    procps-ng net-tools python3-pysocks python3-requests python3-pyscard python3-jinja2 \
    python3-devel \
    meson ninja-build perl-podlators systemd-devel \
    tcpdump bind-utils iputils

# Build pcsc-lite ${PCSC_VERSION} from source (client library + headers). Installs over any
# distro-provided libpcsclite pulled in by python3-pyscard, so both strongSwan (--enable-eap-sim-pcsc,
# links at build time) and pyscard (loads libpcsclite.so.1 at runtime) use the pinned version and
# talk the same protocol as the host pcscd.
RUN cd /tmp && \
    wget -qO pcsc.tar.gz "https://github.com/LudovicRousseau/PCSC/archive/refs/tags/${PCSC_VERSION}.tar.gz" && \
    tar xf pcsc.tar.gz && cd "PCSC-${PCSC_VERSION}" && \
    meson setup builddir --prefix=/usr -Dpolkit=false && \
    ninja -C builddir && ninja -C builddir install && \
    ldconfig && \
    rm -rf /tmp/pcsc.tar.gz "/tmp/PCSC-${PCSC_VERSION}"

# sysmocom pjproject + Asterisk (VoLTE/VoWiFi/IMS-AKA/SMS-over-IMS fork), identical to reference build
COPY patches/asterisk/ /home/asterisk-build/patches/asterisk/
RUN git clone --depth=1 --branch sysmocom/2.14 https://gitea.sysmocom.de/sysmocom/pjproject.git && \
    git clone --depth=1 --branch sysmocom/20.7.0 https://gitea.sysmocom.de/sysmocom/asterisk.git && \
    cd asterisk && \
    git config user.email "build@vowifi" && git config user.name "vowifi build" && \
    git fetch origin f1b60dcd9568c4045512fd0d8b619b9fb91a7f35 && \
    git cherry-pick f1b60dcd9568c4045512fd0d8b619b9fb91a7f35 && \
    for p in /home/asterisk-build/patches/asterisk/*.py; do echo "applying $p"; python3 "$p" || exit 1; done && \
    ln -s ../../../pjproject third-party/pjproject/source && \
    sh bootstrap.sh && \
    ./configure --enable-binary-modules && \
    make menuselect/menuselect menuselect-tree menuselect.makeopts && \
    ./menuselect/menuselect --enable codec_opus --disable BUILD_NATIVE && \
    make -j$(nproc) && \
    make install

# strongSwan ePDG fork (SWu/IKEv2 EAP-AKA + P-CSCF discovery + userspace ESP), identical build flags
RUN git clone --depth=1 --branch jolly/work https://gitea.osmocom.org/ims-volte-vowifi/strongswan-epdg.git && \
    cd strongswan-epdg && \
    patch -i ../02_warnings.patch -p1 && \
    patch -i ../03_eap_sim_pcsc_verify_pin.patch -p1 && \
    autoreconf -if && \
    ./configure --enable-eap-sim-pcsc --enable-p-cscf --enable-save-keys --enable-eap-sim \
                --enable-eap-aka --enable-kernel-libipsec --disable-nls && \
    make -j$(nproc) && \
    make install

RUN pip install panoramisk

# SWu (python IKEv2/IPsec) tunnel dependencies. swu_ike.py replaces strongSwan for the ePDG
# tunnel; it needs pycryptodome/cryptography (IKE + ESP crypto), pyserial (imported by the
# upstream emulator), and mitshell's CryptoMobile + card (USIM/Milenage helpers). strongSwan is
# still built above and kept in the image as a rollback path.
RUN pip install pyserial pycryptodome cryptography \
    "git+https://github.com/mitshell/CryptoMobile.git" \
    "git+https://github.com/mitshell/card.git"

# strongSwan charon plugin toggles (from reference)
COPY p-cscf.conf     /usr/local/etc/strongswan.d/charon/p-cscf.conf
COPY osmo-epdg.conf  /usr/local/etc/strongswan.d/charon/osmo-epdg.conf
COPY strongswan.conf /usr/local/etc/strongswan.conf

# our scripts + templates
COPY ims.updown      /usr/local/etc/ims.updown
COPY pin_keeper.py   /usr/local/bin/pin_keeper.py
COPY ami_usim.py     /usr/local/bin/ami_usim.py
COPY swu_ike.py      /usr/local/bin/swu_ike.py
COPY render.py       /usr/local/bin/render.py
COPY notify.py       /usr/local/bin/notify.py
COPY templates/      /opt/vowifi/templates/
COPY entrypoint.sh   /entrypoint.sh
RUN chmod +x /usr/local/etc/ims.updown /usr/local/bin/*.py /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
