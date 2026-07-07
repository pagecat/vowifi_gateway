#!/bin/sh
# install.sh — one-click installer / lifecycle manager for the VoWiFi→SIP gateway.
#
# Deploys the whole system on any Docker-capable Linux with a PC/SC reader, in one of two
# DEPLOY MODES:
#
#   local   (DEFAULT) — control plane runs NATIVELY on the host (Python venv + systemd unit);
#                       Docker is used only as the ENGINE layer (per-SIM engine containers).
#                       The WebUI is still compiled with a throwaway Node container, so the
#                       host needs no Node/JS toolchain.
#   docker            — control plane AND engine both run in containers (control plane in a
#                       privileged container with the host Docker + pcscd sockets bind-mounted).
#
# In BOTH modes:
#   - Docker + host pcscd are installed and running
#   - pcsc-lite is version-LOCKED (PCSC_VERSION) across the host + every container image so the
#     PC/SC client/server protocol always matches (distro defaults differ -> "Failed to
#     establish context")
#   - the engine image is built from source with all bug-fix patches baked in (engine/patches/*)
#
# Usage:
#   sudo ./install.sh install [--mode local|docker]   # full install (default mode: local)
#   sudo ./install.sh reload  [--mode local|docker] [--no-cache] [--engines]
#   sudo ./install.sh enable-autostart | disable-autostart
#   sudo ./install.sh uninstall [--purge]             # --purge also deletes ./data (+ venv)
#   ./install.sh status | logs
#
# The chosen mode is remembered (persisted under the data dir), so reload/status/logs/uninstall
# don't need --mode again. An explicit --mode or the VOWIFI_MODE env var always overrides.
#
# Config via env (or a .env file next to this script):
#   VOWIFI_MODE            deploy mode: local | docker                (default local)
#   VOWIFI_PORT            host port to publish/serve the WebUI on    (default 8443)
#   VOWIFI_DATA_DIR        runtime data dir                           (default <repo>/data)
#   VOWIFI_ADVERTISE_ADDR  host LAN IP for SIP/WebRTC media           (default: auto-detect)
#   VOWIFI_BIND            control bind addr                          (default 0.0.0.0)
#   PCSC_VERSION           pinned pcsc-lite version                   (default 2.3.3)
set -eu

# ------------------------------------------------------------------ paths & config
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_DIR="$SELF_DIR"
[ -f "$REPO_DIR/.env" ] && . "$REPO_DIR/.env"

VOWIFI_PORT="${VOWIFI_PORT:-8443}"
VOWIFI_DATA_DIR="${VOWIFI_DATA_DIR:-$REPO_DIR/data}"
VOWIFI_BIND="${VOWIFI_BIND:-0.0.0.0}"
VOWIFI_ADVERTISE_ADDR="${VOWIFI_ADVERTISE_ADDR:-}"

CONTROL_IMAGE="vowifi/control"
ENGINE_IMAGE="vowifi/engine"
CONTROL_NAME="vowifi-control"
ENGINE_PREFIX="vowifi-engine-"

# Native (local-mode) control plane bits.
VENV_DIR="$REPO_DIR/control/.venv"
WEBUI_DIST="$REPO_DIR/webui/dist"
SYSTEMD_UNIT="/etc/systemd/system/vowifi-control.service"
# Where the selected deploy mode is remembered between invocations.
MODE_STATE="$VOWIFI_DATA_DIR/install-mode"

# pcsc-lite version pinned across host + both container images so the PC/SC client/server
# protocol always matches (distro defaults differ -> "Failed to establish context").
PCSC_VERSION="${PCSC_VERSION:-2.3.3}"
# Set by ensure_pcscd: 1 if we source-built pcsc-lite on the host (headers already in /usr),
# 0 if the distro package already matched the pin (need the distro -dev pkg for pyscard headers).
PCSC_SOURCE_BUILT=0
# CCID USB driver version, built from source ON THE HOST with local fixes (patches/ccid/*).
# NOT installed by default — run `sudo ./install.sh patch` to build + install it. Needed only
# for the HSIC CCID-Reader (1d99:0016): its firmware always answers "no ICC present" to
# GetSlotStatus even while a card is inserted and powered, so stock libccid never powers
# the card. NotifySlotChange only sets a pending flag; IFDHICCPresence tick probes
# via IccPowerOn/ATR (debounced) and restores prior power state.
# Keep this >= 1.6.2: that release added 1d99:0016 to the supported-reader table, so the
# built driver recognizes the VID/PID out of the box (older/distro libccid < 1.6.2 would
# additionally need the device whitelisted by hand in the bundle's Info.plist).
CCID_VERSION="${CCID_VERSION:-1.6.2}"

# ------------------------------------------------------------------ pretty output
if [ -t 1 ]; then B=$(printf '\033[1m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); R=$(printf '\033[31m'); N=$(printf '\033[0m'); else B=; G=; Y=; R=; N=; fi
info() { printf '%s==>%s %s\n' "$G$B" "$N" "$*"; }
warn() { printf '%s!!%s %s\n'  "$Y$B" "$N" "$*"; }
err()  { printf '%sxx%s %s\n'  "$R$B" "$N" "$*" >&2; }
die()  { err "$@"; exit 1; }

# ------------------------------------------------------------------ helpers
need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "this command needs root — re-run with: sudo $0 $CMD"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# Best-effort primary LAN IPv4 of THIS host (the address SIP/WebRTC clients must reach).
detect_lan_ip() {
  ip=""
  if have ip; then
    ip=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
  fi
  if [ -z "$ip" ] && have hostname; then
    ip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n1)
  fi
  printf '%s' "$ip"
}

# Detect the host package manager and install the given packages.
pkg_install() {
  if   have apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif have dnf;     then dnf install -y "$@"
  elif have yum;     then yum install -y "$@"
  elif have pacman;  then pacman -Sy --noconfirm "$@"
  elif have zypper;  then zypper install -y "$@"
  elif have apk;     then apk add --no-cache "$@"
  else die "no supported package manager found (apt/dnf/yum/pacman/zypper/apk)"
  fi
}

svc_enable_start() {
  # Enable+start a system service across init systems (best-effort).
  if have systemctl; then systemctl enable --now "$1" 2>/dev/null || systemctl start "$1" 2>/dev/null || true
  elif have rc-update; then rc-update add "$1" default 2>/dev/null || true; rc-service "$1" start 2>/dev/null || true
  elif have service; then service "$1" start 2>/dev/null || true
  fi
}

# Ensure pcscd is running AND set to start on boot. pcscd ships differently across distros:
# some socket-activate it (pcscd.socket starts the daemon on first client), some don't enable
# it at all (seen on Armbian) — so a plain `systemctl enable --now pcscd` may leave it stopped
# and not persistent. We enable both the socket and the service, start the daemon now, and
# verify it actually came up (falling back to a manual daemon launch if the units don't exist).
enable_pcscd_autostart() {
  if have systemctl; then
    # Enable the socket (on-boot autostart, incl. socket-activated setups) and the service.
    systemctl enable pcscd.socket 2>/dev/null || true
    systemctl enable pcscd.service 2>/dev/null || systemctl enable pcscd 2>/dev/null || true
    # Start now: the socket triggers the daemon on first use; also start the service directly
    # for distros where the service isn't socket-activated.
    systemctl start pcscd.socket 2>/dev/null || true
    systemctl start pcscd.service 2>/dev/null || systemctl start pcscd 2>/dev/null || true
    # Verify. If neither the daemon nor its socket is present, force the service up once.
    if ! systemctl is-active --quiet pcscd 2>/dev/null && [ ! -S /run/pcscd/pcscd.comm ]; then
      systemctl restart pcscd.service 2>/dev/null || systemctl restart pcscd 2>/dev/null || true
    fi
  else
    svc_enable_start pcscd
  fi
  # Last-resort: if systemd units are absent/broken but the binary exists, launch it detached so
  # the reader is usable this session (autostart on non-systemd hosts is best-effort).
  if [ ! -S /run/pcscd/pcscd.comm ] && have pcscd && ! pgrep -x pcscd >/dev/null 2>&1; then
    mkdir -p /run/pcscd
    pcscd 2>/dev/null || true   # daemonizes by default; harmless if a unit already owns it
  fi
}

data_dir_abs() { CDPATH= cd -- "$VOWIFI_DATA_DIR" 2>/dev/null && pwd -P || printf '%s' "$VOWIFI_DATA_DIR"; }

# ------------------------------------------------------------------ deploy-mode state
persist_mode() {
  mkdir -p "$VOWIFI_DATA_DIR"
  printf '%s\n' "$1" > "$MODE_STATE" 2>/dev/null || true
}

# Detect an EXISTING installation from real artifacts (not just the state file), and which
# plane it uses. Prints: local | docker | none.
#   local  = native systemd unit present
#   docker = control container present
detect_installed_mode() {
  if [ -f "$SYSTEMD_UNIT" ]; then echo local; return; fi
  if have docker && docker container inspect "$CONTROL_NAME" >/dev/null 2>&1; then echo docker; return; fi
  echo none
}

# Resolve the deploy mode. For lifecycle commands (start/stop/status/…): prefer what's actually
# installed, so controls act on the real plane regardless of the state file. Precedence:
#   --mode arg > VOWIFI_MODE env > detected-from-artifacts > persisted state > default(local).
resolve_mode() {
  m="${MODE_ARG:-}"
  [ -z "$m" ] && m="${VOWIFI_MODE:-}"
  if [ -z "$m" ]; then d=$(detect_installed_mode); [ "$d" != none ] && m="$d"; fi
  [ -z "$m" ] && [ -f "$MODE_STATE" ] && m=$(cat "$MODE_STATE" 2>/dev/null || true)
  [ -z "$m" ] && m="local"
  case "$m" in
    local|docker) ;;
    *) die "invalid deploy mode '$m' (use: local | docker)";;
  esac
  MODE="$m"
}

# True (0) if the control plane is currently running.
control_running() {
  if [ "${MODE:-}" = local ]; then
    have systemctl && systemctl is-active --quiet vowifi-control
  else
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTROL_NAME" 2>/dev/null)" = true ]
  fi
}

# ------------------------------------------------------------------ prerequisites
ensure_docker() {
  if have docker && docker info >/dev/null 2>&1; then
    info "Docker present ($(docker --version | awk '{print $3}' | tr -d ,))"
    return
  fi
  if ! have docker; then
    info "installing Docker via get.docker.com…"
    if have curl; then curl -fsSL https://get.docker.com | sh
    elif have wget; then wget -qO- https://get.docker.com | sh
    else die "need curl or wget to install Docker"
    fi
  fi
  svc_enable_start docker
  docker info >/dev/null 2>&1 || die "Docker installed but the daemon is not running"
  info "Docker ready"
}

ensure_pcscd() {
  # We PIN pcsc-lite to $PCSC_VERSION everywhere (host pcscd + container client libs) so the
  # PC/SC client/server protocol always matches — distro-default versions differ and cause
  # "Failed to establish context" between a client and the host daemon.  In BOTH deploy modes
  # the reader is owned by the HOST pcscd; engine containers (and, in docker mode, the control
  # container) are pcscd clients over the shared /run/pcscd socket.
  installed_ver=""
  if have pcscd; then installed_ver=$(pcscd --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1); fi

  if [ "$installed_ver" = "$PCSC_VERSION" ]; then
    info "host pcscd already at pinned version $PCSC_VERSION"
    PCSC_SOURCE_BUILT=0
  else
    # Install the CCID USB driver from the distro (its IFDHandler ABI is stable across pcscd
    # 2.x, so the distro driver works with our source-built pcscd), plus build deps.
    info "host pcscd is '${installed_ver:-none}', pinning to $PCSC_VERSION (building from source)…"
    if   have apt-get; then pkg_install libccid libudev-dev libsystemd-dev meson ninja-build flex pkg-config gcc wget ca-certificates
    elif have dnf || have yum; then pkg_install ccid systemd-devel meson ninja-build flex pkgconf-pkg-config gcc perl-podlators wget
    elif have pacman;  then pkg_install ccid meson ninja flex pkgconf gcc wget
    elif have zypper;  then pkg_install pcsc-ccid systemd-devel meson ninja flex pkg-config gcc wget
    else pkg_install ccid meson ninja flex gcc wget
    fi
    _build_pcsclite_host
    PCSC_SOURCE_BUILT=1
  fi
  enable_pcscd_autostart
  # pcscd may be socket-activated (daemon starts on first client), so the socket can be absent
  # until a reader is used — that's fine. If it IS present, confirm; else just note it.
  if [ -S /run/pcscd/pcscd.comm ] || { have systemctl && systemctl is-active --quiet pcscd 2>/dev/null; }; then
    info "host pcscd running + set to start on boot"
  else
    warn "pcscd not active yet — it is enabled for boot and will start on first reader use"
  fi
}

# Build + install the CCID USB driver $CCID_VERSION from source with a chosen SET of the
# fixes under patches/ccid/* applied. Args: $1 = short set label (used for the idempotency
# marker + logs), remaining args = patch filenames (under patches/ccid/) to apply in order.
# Patch sets (see the `patch*` subcommands):
#   01_hsic_slot_status.patch   HSIC 1d99:0016 broken GetSlotStatus — firmware always reports
#                               "no ICC present". NotifySlotChange sets pending; IFDHICCPresence
#                               tick probes via IccPowerOn/ATR (debounced). Base fix; safe for all cards.
#   02_hsic_malformed_atr.patch HSIC firmware drops the final TCK byte from the ATR; this
#                               patch synthesizes it at power-on (ISO 7816-3 XOR) and falls back
#                               to relaxed validation if repair fails. Fixes SCardConnect 607
#                               for (U)SIMs that work on other readers.
# The build installs into the pcsc-lite usbdropdir, replacing the distro libccid bundle files.
# Idempotent via a per-set marker file (switching sets rebuilds); on apt systems the distro
# libccid package is held so an upgrade can't clobber the patched driver.
# OPT-IN: not part of `install` — run `sudo ./install.sh patch | patch2 | patchall`.
ensure_ccid_host() {
  set_label="$1"; shift
  ccid_patches="$*"
  drivers_dir=$(pkg-config libpcsclite --variable usbdropdir 2>/dev/null || true)
  [ -n "$drivers_dir" ] || drivers_dir=/usr/lib/pcsc/drivers
  ccid_marker="$drivers_dir/ifd-ccid.bundle/Contents/.vowifi-ccid-${CCID_VERSION}-${set_label}"
  if [ -f "$ccid_marker" ]; then
    info "patched CCID driver $CCID_VERSION (set: $set_label) already installed ($drivers_dir)"
    return
  fi
  info "building CCID driver $CCID_VERSION from source — patch set '$set_label' ($ccid_patches)…"
  if   have apt-get; then
    pkg_install meson ninja-build flex gcc pkg-config perl patch wget ca-certificates libusb-1.0-0-dev zlib1g-dev
    [ -f /usr/include/PCSC/pcsclite.h ] || pkg_install libpcsclite-dev
  elif have dnf || have yum; then
    pkg_install meson ninja-build flex gcc pkgconf-pkg-config perl patch wget libusb1-devel zlib-devel
    [ -f /usr/include/PCSC/pcsclite.h ] || pkg_install pcsc-lite-devel
  elif have pacman;  then
    pkg_install meson ninja flex gcc pkgconf perl patch wget libusb zlib
  elif have zypper;  then
    pkg_install meson ninja flex gcc pkg-config perl patch wget libusb-1_0-devel zlib-devel
    [ -f /usr/include/PCSC/pcsclite.h ] || pkg_install pcsc-lite-devel
  elif have apk;     then
    pkg_install meson ninja flex gcc pkgconfig perl patch wget musl-dev libusb-dev zlib-dev
    [ -f /usr/include/PCSC/pcsclite.h ] || pkg_install pcsc-lite-dev
  fi
  tmp=$(mktemp -d)
  ( cd "$tmp" \
    && { curl -fsSLo ccid.tar.gz "https://github.com/LudovicRousseau/CCID/archive/refs/tags/${CCID_VERSION}.tar.gz" \
         || wget -qO ccid.tar.gz "https://github.com/LudovicRousseau/CCID/archive/refs/tags/${CCID_VERSION}.tar.gz"; } \
    && tar xf ccid.tar.gz && cd "CCID-${CCID_VERSION}" \
    && for p in $ccid_patches; do echo "applying $p"; patch -p1 < "$REPO_DIR/patches/ccid/$p" || exit 1; done \
    && meson setup builddir \
    && ninja -C builddir && ninja -C builddir install \
  ) || die "failed to build CCID driver $CCID_VERSION from source"
  rm -rf "$tmp"
  # drop any other-set markers so `status`/idempotency reflect the set just installed
  rm -f "$drivers_dir/ifd-ccid.bundle/Contents/.vowifi-ccid-${CCID_VERSION}-"* 2>/dev/null || true
  touch "$ccid_marker" 2>/dev/null || true
  # keep a distro libccid upgrade from clobbering the patched bundle files
  if have apt-mark; then apt-mark hold libccid >/dev/null 2>&1 || true; fi
  # reload the driver if pcscd is already running
  if have systemctl; then systemctl restart pcscd 2>/dev/null || true; fi
  info "patched CCID driver $CCID_VERSION (set: $set_label) installed to $drivers_dir"
}

_build_pcsclite_host() {
  # Build + install pcsc-lite $PCSC_VERSION to /usr on the host (client lib + headers + daemon),
  # and install a systemd unit so it runs as the reader daemon. Idempotent.
  tmp=$(mktemp -d)
  ( cd "$tmp" \
    && { curl -fsSLo pcsc.tar.gz "https://github.com/LudovicRousseau/PCSC/archive/refs/tags/${PCSC_VERSION}.tar.gz" \
         || wget -qO pcsc.tar.gz "https://github.com/LudovicRousseau/PCSC/archive/refs/tags/${PCSC_VERSION}.tar.gz"; } \
    && tar xf pcsc.tar.gz && cd "PCSC-${PCSC_VERSION}" \
    && meson setup builddir --prefix=/usr -Dpolkit=false \
    && ninja -C builddir && ninja -C builddir install \
  ) || die "failed to build pcsc-lite $PCSC_VERSION from source"
  ldconfig 2>/dev/null || true
  rm -rf "$tmp"
  # Ensure a systemd unit + socket exist (meson installs them under /usr/lib/systemd/system).
  if have systemctl; then systemctl daemon-reload 2>/dev/null || true; fi
  info "host pcscd built + installed at $PCSC_VERSION"
}

# ------------------------------------------------------------------ image builds
# Build the engine image ONLY if it is missing, or if forced ($1 non-empty / --no-cache).
# The engine image is large and slow to build (~10-15 min: compiles Asterisk + pcsc-lite + the
# Python SWu tunnel deps), and it bakes every bug-fix patch under engine/patches/* via the
# Dockerfile — so an unforced reinstall reuses the existing patched image instead of rebuilding it.
ensure_engine_image() {
  force="${1:-}"
  if [ -z "$force" ] && [ -z "$NOCACHE_FLAG" ] && docker image inspect "$ENGINE_IMAGE" >/dev/null 2>&1; then
    info "engine image $ENGINE_IMAGE present — reusing (patches from engine/patches/* are baked in). Use 'reload --engines' or '--no-cache' to force a rebuild."
    return
  fi
  info "building engine image ($ENGINE_IMAGE) from source — long; compiles Asterisk+pcsc-lite+Python SWu tunnel deps and bakes engine/patches/*…"
  # shellcheck disable=SC2086
  docker build $NOCACHE_FLAG --build-arg "PCSC_VERSION=$PCSC_VERSION" -t "$ENGINE_IMAGE" "$REPO_DIR/engine"
  info "engine image built"
}

build_control_image() {
  info "building control image ($CONTROL_IMAGE) from source (WebUI + FastAPI)…"
  # shellcheck disable=SC2086
  docker build $NOCACHE_FLAG --build-arg "PCSC_VERSION=$PCSC_VERSION" -t "$CONTROL_IMAGE" -f "$REPO_DIR/control/Dockerfile" "$REPO_DIR"
  info "control image built"
}

# Compile the React WebUI to webui/dist using a throwaway Node container — so LOCAL mode needs
# no Node/JS toolchain on the host. Builds in an isolated dir inside the container (ignores any
# host node_modules that might be built for another arch), then copies dist back to the host.
build_webui_local() {
  info "building WebUI (webui/dist) via a throwaway node:22-alpine container (no host Node needed)…"
  docker run --rm -v "$REPO_DIR/webui":/host-webui node:22-alpine sh -euc '
    cp -a /host-webui /build && cd /build && rm -rf node_modules dist
    npm ci
    npm run build
    rm -rf /host-webui/dist && cp -a /build/dist /host-webui/dist
  '
  [ -f "$WEBUI_DIST/index.html" ] || die "WebUI build produced no dist/index.html"
  info "WebUI built at $WEBUI_DIST"
}

# ------------------------------------------------------------------ native (local) control plane
# Install host packages the native control plane needs: python venv + the toolchain to build
# pyscard (SWIG binding) against the pinned pcsc-lite, plus headers for cryptography if wheels
# are unavailable. pcsc-lite headers come from our source build (if we did one) or the distro
# -dev package (version already matches the pin, since ensure_pcscd aligned it).
ensure_control_local_deps() {
  info "installing native control-plane dependencies (python venv + pyscard build toolchain)…"
  if   have apt-get; then
    pkg_install python3 python3-venv python3-pip python3-dev swig gcc pkg-config libffi-dev libssl-dev
    if [ "$PCSC_SOURCE_BUILT" = 0 ] && [ ! -f /usr/include/PCSC/pcsclite.h ]; then pkg_install libpcsclite-dev; fi
  elif have dnf || have yum; then
    pkg_install python3 python3-pip python3-devel swig gcc pkgconf-pkg-config libffi-devel openssl-devel
    if [ "$PCSC_SOURCE_BUILT" = 0 ] && [ ! -f /usr/include/PCSC/pcsclite.h ]; then pkg_install pcsc-lite-devel; fi
  elif have pacman;  then
    pkg_install python python-pip swig gcc pkgconf libffi openssl
    if [ "$PCSC_SOURCE_BUILT" = 0 ] && [ ! -f /usr/include/PCSC/pcsclite.h ]; then pkg_install pcsclite; fi
  elif have zypper;  then
    pkg_install python3 python3-pip python3-devel swig gcc pkg-config libffi-devel libopenssl-devel
    if [ "$PCSC_SOURCE_BUILT" = 0 ] && [ ! -f /usr/include/PCSC/pcsclite.h ]; then pkg_install pcsc-lite-devel; fi
  elif have apk;     then
    pkg_install python3 python3-dev py3-pip swig gcc musl-dev pkgconfig libffi-dev openssl-dev
    if [ "$PCSC_SOURCE_BUILT" = 0 ] && [ ! -f /usr/include/PCSC/pcsclite.h ]; then pkg_install pcsc-lite-dev; fi
  fi
}

setup_venv() {
  info "creating Python venv + installing control requirements ($VENV_DIR)…"
  [ -d "$VENV_DIR" ] || python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet --upgrade pip wheel
  "$VENV_DIR/bin/pip" install --quiet -r "$REPO_DIR/control/requirements.txt"
  info "venv ready"
}

# Write + (re)start the native control-plane systemd unit. Runs as root (needs the reader via
# host pcscd + the Docker socket to manage engine containers). Because the control plane runs
# ON the host, VOWIFI_HOST_DATA == VOWIFI_DATA (the real host path the manager hands to engine
# bind-mounts). Engines reach it back over host.docker.internal:<port> (engine.start adds the
# host-gateway extra_host), same as in docker mode.
run_control_local() {
  have systemctl || die "local mode needs systemd (systemctl not found). Re-run with --mode docker."
  mkdir -p "$VOWIFI_DATA_DIR"
  DATA_ABS=$(data_dir_abs)
  LAN_IP="$VOWIFI_ADVERTISE_ADDR"
  [ -z "$LAN_IP" ] && LAN_IP=$(detect_lan_ip)
  [ -z "$LAN_IP" ] && warn "could not auto-detect a LAN IP; set VOWIFI_ADVERTISE_ADDR — SIP/WebRTC audio needs a routable host address"

  info "installing systemd unit $SYSTEMD_UNIT (native control plane)"
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=VoWiFi Gateway control surface (native / manager + WebUI)
After=network-online.target pcscd.service docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR/control
Environment=VOWIFI_DATA=$DATA_ABS
Environment=VOWIFI_HOST_DATA=$DATA_ABS
Environment=VOWIFI_WEBUI=$WEBUI_DIST
Environment=VOWIFI_HTTP_PORT=$VOWIFI_PORT
Environment=VOWIFI_BIND=$VOWIFI_BIND
Environment=VOWIFI_ADVERTISE_ADDR=$LAN_IP
Environment=VOWIFI_ENGINE_IMAGE=$ENGINE_IMAGE
Environment=VOWIFI_MANAGER_URL=https://host.docker.internal:$VOWIFI_PORT
Environment=VOWIFI_PCSCD_DIR=/run/pcscd
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/python run.py
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable vowifi-control >/dev/null 2>&1 || true
  systemctl restart vowifi-control
  info "started native control plane on https://${LAN_IP:-<host>}:${VOWIFI_PORT}"
}

remove_control_local() {
  if have systemctl; then
    systemctl disable --now vowifi-control >/dev/null 2>&1 || true
  fi
  if [ -f "$SYSTEMD_UNIT" ]; then
    rm -f "$SYSTEMD_UNIT"
    have systemctl && systemctl daemon-reload 2>/dev/null || true
  fi
}

# ------------------------------------------------------------------ containerized control plane
run_control() {
  mkdir -p "$VOWIFI_DATA_DIR"
  DATA_ABS=$(data_dir_abs)
  LAN_IP="$VOWIFI_ADVERTISE_ADDR"
  [ -z "$LAN_IP" ] && LAN_IP=$(detect_lan_ip)
  [ -z "$LAN_IP" ] && warn "could not auto-detect a LAN IP; set VOWIFI_ADVERTISE_ADDR — SIP/WebRTC audio needs a routable host address"

  docker rm -f "$CONTROL_NAME" >/dev/null 2>&1 || true
  info "starting control plane container ($CONTROL_NAME) on https://${LAN_IP:-<host>}:${VOWIFI_PORT}"
  docker run -d --name "$CONTROL_NAME" \
    --privileged \
    --restart unless-stopped \
    -p "${VOWIFI_PORT}:8443" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /run/pcscd:/run/pcscd \
    -v "${DATA_ABS}:/data" \
    -e VOWIFI_DATA=/data \
    -e VOWIFI_HOST_DATA="${DATA_ABS}" \
    -e VOWIFI_HTTP_PORT=8443 \
    -e VOWIFI_BIND="${VOWIFI_BIND}" \
    -e VOWIFI_ADVERTISE_ADDR="${LAN_IP}" \
    -e VOWIFI_MANAGER_URL="https://host.docker.internal:${VOWIFI_PORT}" \
    -e VOWIFI_ENGINE_IMAGE="${ENGINE_IMAGE}" \
    -e VOWIFI_PCSCD_DIR=/run/pcscd \
    "$CONTROL_IMAGE"
}

engine_names() { docker ps -a --format '{{.Names}}' 2>/dev/null | grep "^${ENGINE_PREFIX}" || true; }

# ------------------------------------------------------------------ subcommands
cmd_install() {
  need_root
  resolve_mode
  info "VoWiFi gateway install — repo: $REPO_DIR  (mode: ${B}$MODE${N})"
  # The engine image compiles Asterisk + pcsc-lite + the Python SWu tunnel deps from source. On
  # low-power ARM boards (Raspberry Pi, Armbian SBCs) this first build can take 20-30 minutes —
  # only once, since later installs reuse the built image. Warn up front so a long, quiet build
  # isn't mistaken for a hang.
  if ! docker image inspect "$ENGINE_IMAGE" >/dev/null 2>&1; then
    warn "the engine image builds from source (Asterisk + pcsc-lite + SWu tunnel deps). On low-power ARM"
    warn "machines this can take 20-30 minutes — this is normal, please be patient. It runs only once;"
    warn "later installs/reloads reuse the built image."
  fi
  ensure_docker
  ensure_pcscd
  ensure_engine_image
  persist_mode "$MODE"
  if [ "$MODE" = docker ]; then
    build_control_image
    run_control
  else
    build_webui_local
    ensure_control_local_deps
    setup_venv
    run_control_local
  fi
  DATA_ABS=$(data_dir_abs)
  LAN_IP="${VOWIFI_ADVERTISE_ADDR:-$(detect_lan_ip)}"
  printf '\n'
  info "install complete (mode: $MODE)"
  printf '   %sWebUI:%s   https://%s:%s\n' "$B" "$N" "${LAN_IP:-<host-ip>}" "$VOWIFI_PORT"
  printf '   %sData:%s    %s\n' "$B" "$N" "$DATA_ABS"
  if [ "$MODE" = local ]; then
    printf '   %sControl:%s native systemd service (vowifi-control); engines run in Docker\n' "$B" "$N"
  else
    printf '   %sControl:%s Docker container (%s); engines run in Docker\n' "$B" "$N" "$CONTROL_NAME"
  fi
  printf '   %sManage:%s  %s status | logs | reload | disable-autostart | uninstall\n' "$B" "$N" "$0"
  printf '   Accept the self-signed cert in your browser, then provision your SIM in the dashboard.\n'
}

cmd_reload() {
  need_root
  resolve_mode
  RECREATE_ENGINES=0
  for a in $ARGS; do [ "$a" = "--engines" ] && RECREATE_ENGINES=1; done
  info "reload (mode: $MODE)"
  # Engine image: only rebuilt on --engines or --no-cache (otherwise reuse the patched image).
  if [ "$RECREATE_ENGINES" = 1 ] || [ -n "$NOCACHE_FLAG" ]; then
    ensure_engine_image force
  else
    ensure_engine_image
  fi
  if [ "$MODE" = docker ]; then
    build_control_image
    run_control
  else
    build_webui_local
    ensure_control_local_deps
    setup_venv
    run_control_local
  fi
  if [ "$RECREATE_ENGINES" = 1 ]; then
    warn "engines will be re-created by the control plane on next start/provision (image updated)"
    for n in $(engine_names); do docker rm -f "$n" >/dev/null 2>&1 || true; done
  fi
  info "reload complete (data preserved)"
}

cmd_start() {
  need_root
  resolve_mode
  if [ "$MODE" = local ]; then
    have systemctl || die "local mode needs systemd"
    systemctl start vowifi-control && info "control plane started (systemd)" || warn "could not start vowifi-control"
  else
    docker start "$CONTROL_NAME" >/dev/null 2>&1 && info "control plane started (docker)" || warn "control container not found"
  fi
}

cmd_stop() {
  need_root
  resolve_mode
  if [ "$MODE" = local ]; then
    have systemctl || die "local mode needs systemd"
    systemctl stop vowifi-control && info "control plane stopped (systemd)" || warn "could not stop vowifi-control"
  else
    docker stop "$CONTROL_NAME" >/dev/null 2>&1 && info "control plane stopped (docker)" || warn "control container not found"
  fi
  info "note: engine containers keep running; the control plane just stops managing them until restarted"
}

cmd_restart() {
  need_root
  resolve_mode
  if [ "$MODE" = local ]; then
    have systemctl || die "local mode needs systemd"
    systemctl restart vowifi-control && info "control plane restarted (systemd)" || warn "could not restart vowifi-control"
  else
    docker restart "$CONTROL_NAME" >/dev/null 2>&1 && info "control plane restarted (docker)" || warn "control container not found"
  fi
}

cmd_enable_autostart() {
  need_root
  resolve_mode
  if [ "$MODE" = local ]; then
    have systemctl && systemctl enable vowifi-control >/dev/null 2>&1 && info "control autostart ON (systemd)" || warn "systemd unit not found"
  else
    docker update --restart unless-stopped "$CONTROL_NAME" >/dev/null 2>&1 && info "control autostart ON" || warn "control container not found"
  fi
  for n in $(engine_names); do docker update --restart unless-stopped "$n" >/dev/null 2>&1 || true; done
}

cmd_disable_autostart() {
  need_root
  resolve_mode
  if [ "$MODE" = local ]; then
    have systemctl && systemctl disable vowifi-control >/dev/null 2>&1 && info "control autostart OFF (systemd)" || warn "systemd unit not found"
  else
    docker update --restart no "$CONTROL_NAME" >/dev/null 2>&1 && info "control autostart OFF" || warn "control container not found"
  fi
  for n in $(engine_names); do docker update --restart no "$n" >/dev/null 2>&1 || true; done
  info "note: already-running components keep running until stopped or the host reboots"
}

cmd_uninstall() {
  need_root
  resolve_mode
  PURGE=0
  for a in $ARGS; do [ "$a" = "--purge" ] && PURGE=1; done
  info "uninstalling (mode: $MODE)…"
  # Tear down BOTH possible control planes so switching modes leaves nothing behind.
  info "removing native control plane (if any)…"
  remove_control_local
  info "removing vowifi containers…"
  docker rm -f "$CONTROL_NAME" >/dev/null 2>&1 || true
  for n in $(engine_names); do docker rm -f "$n" >/dev/null 2>&1 || true; done
  if [ "$PURGE" = 1 ]; then
    # Full teardown: also drop images (incl. the slow, patched engine image) and data+venv.
    info "removing vowifi images…"
    docker rmi -f "$CONTROL_IMAGE" "$ENGINE_IMAGE" >/dev/null 2>&1 || true
    warn "purging data dir: $(data_dir_abs) and venv $VENV_DIR"
    rm -rf "$VOWIFI_DATA_DIR" "$VENV_DIR"
  else
    # Keep the ~15-20 min patched engine image (and the control image) so a reinstall reuses
    # them; only the running components are torn down. Data + venv are preserved too.
    docker rmi -f "$CONTROL_IMAGE" >/dev/null 2>&1 || true
    info "data kept at $(data_dir_abs); engine image + venv preserved (use --purge to delete all). Docker & pcscd left installed."
  fi
  info "uninstall complete"
}

cmd_status() {
  resolve_mode
  printf '%sMode:%s    %s\n' "$B" "$N" "$MODE"
  printf '%sControl:%s\n' "$B" "$N"
  if [ "$MODE" = local ]; then
    if have systemctl; then
      systemctl is-active vowifi-control >/dev/null 2>&1 \
        && printf '  vowifi-control  %s\n' "$(systemctl show -p ActiveState -p SubState --value vowifi-control 2>/dev/null | tr '\n' ' ')" \
        || printf '  vowifi-control  (not running)\n'
    fi
  else
    docker ps -a --filter "name=^${CONTROL_NAME}$" --format '  {{.Names}}  {{.Status}}  {{.Ports}}' 2>/dev/null || true
  fi
  printf '%sEngines:%s\n' "$B" "$N"
  docker ps -a --filter "name=^${ENGINE_PREFIX}" --format '  {{.Names}}  {{.Status}}' 2>/dev/null || true
}

# Opt-in: build + install the patched CCID driver (patches/ccid/*) on the host. Kept out of
# the default install because it replaces the distro libccid — only needed for quirky readers
# (e.g. HSIC 1d99:0016, whose GetSlotStatus always reports "no card").
#   patch     base fix only (01) — HSIC presence detection; safe for every card incl. eSIM.
#   patch2    compatibility fix only (02) — synthesize missing ATR TCK for HSIC reader.
#   patchall  both (01 + 02).
cmd_patch() {
  need_root
  ensure_ccid_host slot 01_hsic_slot_status.patch
}

cmd_patch2() {
  need_root
  ensure_ccid_host atr 02_hsic_malformed_atr.patch
}

cmd_patchall() {
  need_root
  ensure_ccid_host all 01_hsic_slot_status.patch 02_hsic_malformed_atr.patch
}

cmd_logs() {
  resolve_mode
  # `|| true` so that Ctrl-C'ing out of a follow (non-zero exit) doesn't abort the caller —
  # matters when invoked from the interactive control menu.
  if [ "$MODE" = local ]; then
    have systemctl || die "systemd not available"
    journalctl -fu vowifi-control || true
  else
    docker logs -f "$CONTROL_NAME" || true
  fi
}

# Default action when invoked with no subcommand. Multi-functional:
#   - NOT installed  -> run the installer (needs root).
#   - installed      -> auto-detect the mode and offer basic controls. On a TTY this is an
#                       interactive menu; non-interactively it prints status + the command list.
cmd_auto() {
  installed=$(detect_installed_mode)
  if [ "$installed" = none ]; then
    info "no existing installation detected — installing…"
    cmd_install
    return
  fi
  MODE="$installed"
  info "existing installation detected — mode: ${B}$MODE${N}"
  cmd_status
  if [ ! -t 0 ]; then
    printf '\n%sControls:%s %s start | stop | restart | enable-autostart | disable-autostart | reload | logs | uninstall\n' \
      "$B" "$N" "$0"
    return
  fi
  # Interactive control menu.
  autostart_state() {
    if [ "$MODE" = local ]; then
      systemctl is-enabled --quiet vowifi-control 2>/dev/null && echo on || echo off
    else
      case "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$CONTROL_NAME" 2>/dev/null)" in
        ""|no) echo off;; *) echo on;; esac
    fi
  }
  while :; do
    control_running && run="running" || run="stopped"
    printf '\n%sVoWiFi control (%s) — %s, autostart %s%s\n' "$B" "$MODE" "$run" "$(autostart_state)" "$N"
    printf '  1) %s control plane\n' "$([ "$run" = running ] && echo stop || echo start)"
    printf '  2) restart control plane\n'
    printf '  3) %s autostart\n' "$([ "$(autostart_state)" = on ] && echo disable || echo enable)"
    printf '  4) status\n'
    printf '  5) logs (follow)\n'
    printf '  6) reload (rebuild + restart)\n'
    printf '  7) uninstall\n'
    printf '  q) quit\n'
    printf 'choose: '
    read -r choice || break
    case "$choice" in
      1) [ "$run" = running ] && cmd_stop || cmd_start ;;
      2) cmd_restart ;;
      3) [ "$(autostart_state)" = on ] && cmd_disable_autostart || cmd_enable_autostart ;;
      4) cmd_status ;;
      5) cmd_logs ;;
      6) cmd_reload ;;
      7) cmd_uninstall; break ;;
      q|Q|"") break ;;
      *) warn "unknown choice: $choice" ;;
    esac
  done
}

usage() {
  cat <<EOF
${B}VoWiFi→SIP gateway installer${N}

  $0                      auto: install if absent, else show status + control menu
  $0 install [--mode local|docker]   build + run (default mode: local)
  $0 reload  [--mode local|docker] [--no-cache] [--engines]   rebuild + restart (keep data)
  $0 start | stop | restart          control-plane lifecycle (systemd or docker per mode)
  $0 enable-autostart     start on boot
  $0 disable-autostart    do not start on boot
  $0 uninstall [--purge]  remove vowifi containers/images/service (--purge also deletes data+venv)
  $0 status               show mode + component status
  $0 logs                 follow control-plane logs
  $0 patch                build + install the CCID driver with the base HSIC fix (01) — opt-in,
                          for the HSIC 1d99:0016 reader (safe for every card, incl. physical eSIM)
  $0 patch2               add only the ATR-compatibility fix (02) for non-compliant (U)SIM ATRs
  $0 patchall             apply both CCID patches (01 + 02); use for SIMs that need the ATR fix

${B}Modes:${N}
  local  (default) control plane runs natively (venv + systemd 'vowifi-control');
                   Docker is the engine layer only. WebUI compiled via a throwaway
                   Node container, so the host needs no Node.
  docker           control plane AND engine run in containers.
  Both modes version-lock pcsc-lite ($PCSC_VERSION) and bake engine patches.
  Run with no arguments to auto-install, or to manage an existing install.

Env: VOWIFI_MODE(=local) VOWIFI_PORT(=$VOWIFI_PORT) VOWIFI_DATA_DIR(=$VOWIFI_DATA_DIR)
     VOWIFI_ADVERTISE_ADDR(auto) VOWIFI_BIND(=$VOWIFI_BIND) PCSC_VERSION(=$PCSC_VERSION)
EOF
}

# ------------------------------------------------------------------ dispatch
CMD="${1:-}"; [ $# -gt 0 ] && shift || true

# Parse args: extract --mode <val> / --mode=<val>, collect the rest into ARGS, note --no-cache.
# The bottom `shift` is always safe: we only reach it inside `while [ $# -gt 0 ]`, and the
# `--mode <val>` branch consumes its value with `shift 2` + `continue` (avoids a bare `shift`
# on an empty arg list, which is a fatal special-builtin error in dash even with `|| true`).
MODE_ARG=""
ARGS=""
NOCACHE_FLAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)
      [ $# -ge 2 ] || die "--mode requires a value: local | docker"
      MODE_ARG="$2"; shift 2; continue ;;
    --mode=*)   MODE_ARG="${1#--mode=}" ;;
    --no-cache) NOCACHE_FLAG="--no-cache"; ARGS="$ARGS $1" ;;
    *)          ARGS="$ARGS $1" ;;
  esac
  shift
done

case "$CMD" in
  install)            cmd_install ;;
  reload)             cmd_reload ;;
  start)              cmd_start ;;
  stop)               cmd_stop ;;
  restart)            cmd_restart ;;
  enable-autostart)   cmd_enable_autostart ;;
  disable-autostart)  cmd_disable_autostart ;;
  uninstall)          cmd_uninstall ;;
  status)             cmd_status ;;
  logs)               cmd_logs ;;
  patch)              cmd_patch ;;
  patch2)             cmd_patch2 ;;
  patchall)           cmd_patchall ;;
  "")                 cmd_auto ;;
  -h|--help|help)     usage ;;
  *) err "unknown command: $CMD"; usage; exit 1 ;;
esac
