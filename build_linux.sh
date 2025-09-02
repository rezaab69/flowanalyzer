#!/usr/bin/env bash
# Installs prerequisites on Linux and builds the Flow Analyzer program
# Usage: ./build_linux.sh
set -euo pipefail

# -------------------- helpers --------------------
log()  { echo -e "[+] $*"; }
err()  { echo -e "[!] $*" >&2; }
need() { command -v "$1" >/dev/null 2>&1; }

# -------------------- distro install --------------------
install_prereqs() {
  if need apt-get; then
    log "Using apt-get (Debian/Ubuntu). Updating and installing packages..."
    sudo apt-get update -y
    sudo apt-get install -y \
      build-essential cmake git pkg-config \
      libpcap-dev libssl-dev zlib1g-dev
  elif need dnf; then
    log "Using dnf (Fedora/RHEL). Installing packages..."
    sudo dnf install -y \
      @development-tools cmake git pkgconfig \
      libpcap-devel openssl-devel zlib-devel
  elif need pacman; then
    log "Using pacman (Arch). Installing packages..."
    sudo pacman -Syu --noconfirm \
      base-devel cmake git pkgconf libpcap openssl zlib
  elif need zypper; then
    log "Using zypper (openSUSE). Installing packages..."
    sudo zypper refresh
    sudo zypper install -y -t pattern devel_basis
    sudo zypper install -y cmake git pkg-config libpcap-devel libopenssl-devel zlib-devel
  else
    err "Unsupported package manager. Please install: gcc/g++, make, cmake, git, pkg-config, libpcap dev headers, OpenSSL dev headers, and zlib dev headers."
    exit 1
  fi
}

# -------------------- pcapplusplus install --------------------
have_pcapplusplus() {
  # Check for libraries in common locations
  if ldconfig -p 2>/dev/null | grep -q "libPcap++"; then return 0; fi
  if [ -f /usr/local/lib/libPcap++.so ] || [ -f /usr/local/lib64/libPcap++.so ] || \
     [ -f /usr/lib/libPcap++.so ]       || [ -f /usr/lib64/libPcap++.so ] || \
     [ -f /usr/local/lib/libPcap++.a ]  || [ -f /usr/lib/libPcap++.a ]; then
    return 0
  fi
  return 1
}

install_pcapplusplus() {
  if have_pcapplusplus; then
    log "PcapPlusPlus appears to be installed. Skipping source build."
    return 0
  fi

  log "PcapPlusPlus not found. Building and installing from source (requires sudo)..."
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  pushd "$tmpdir" >/dev/null

  git clone --depth 1 https://github.com/seladb/PcapPlusPlus.git
  cd PcapPlusPlus

  if [ -f ./configure-linux.sh ]; then
    log "Using legacy configure-linux.sh"
    ./configure-linux.sh --default
    make -j"$(nproc)"
    sudo make install
  else
    log "Using CMake build"
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF
    cmake --build build -j"$(nproc)"
    sudo cmake --install build
  fi

  # Ensure include dir name matches project includes (PcapPlusPlus)
  if [ -d /usr/local/include/pcapplusplus ] && [ ! -d /usr/local/include/PcapPlusPlus ]; then
    log "Creating compatibility symlink: /usr/local/include/PcapPlusPlus -> /usr/local/include/pcapplusplus"
    sudo ln -s /usr/local/include/pcapplusplus /usr/local/include/PcapPlusPlus || true
  fi

  popd >/dev/null
}

# -------------------- build project --------------------
build_project() {
  # Detect library directories
  LIB_DIRS=(/usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64)
  LFLAGS=""
  for d in "${LIB_DIRS[@]}"; do
    [ -d "$d" ] && LFLAGS+=" -L$d -Wl,-rpath,$d"
  done

  CXXFLAGS="-std=c++17 -O2 -Wall -Wextra"
  INCLUDES="-I/usr/local/include -I/usr/include"
  LIBS="-lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread"

  log "Compiling flow_analyzer..."
  g++ $CXXFLAGS $INCLUDES main.cpp flow_analyzer.cpp config.cpp -o flow_analyzer $LFLAGS $LIBS
  log "Build complete: ./flow_analyzer"
}

# -------------------- main --------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log "Installing prerequisites..."
install_prereqs

log "Ensuring PcapPlusPlus is installed..."
install_pcapplusplus

log "Building the program..."
build_project

log "Done. You can run: ./flow_analyzer <pcap_file> [options]"