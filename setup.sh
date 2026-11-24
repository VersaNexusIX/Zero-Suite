#!/usr/bin/env bash
set -euo pipefail

ACID="\\033[1;38;2;204;255;0m"
PAPER="\\033[38;2;242;242;238m"
STEEL="\\033[38;2;138;138;133m"
CRIT="\\033[1;38;2;255;59;48m"
RESET="\\033[0m"

log() { printf "%b[ZERO SETUP]%b %b%s%b\\n" "$ACID" "$RESET" "$PAPER" "$1" "$RESET"; }
warn() { printf "%b[ZERO WARN ]%b %b%s%b\\n" "$CRIT" "$RESET" "$STEEL" "$1" "$RESET"; }

IS_TERMUX=0
if [ -n "${PREFIX:-}" ] && [[ "$PREFIX" == *"com.termux"* ]]; then
  IS_TERMUX=1
fi

log "Initializing Zero Suite v1.0 automated bootstrap..."

if ! command -v python3 >/dev/null 2>&1; then
  log "Python 3 not found. Installing runtime..."
  if [ "$IS_TERMUX" -eq 1 ]; then
    pkg update -y && pkg install -y python git curl openssl
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y python3 python3-venv python3-pip git curl openssl
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 python3-pip git curl openssl
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm python python-pip git curl openssl
  elif command -v brew >/dev/null 2>&1; then
    brew install python git curl openssl
  else
    warn "Unsupported package manager. Install Python 3.11+ manually and re-run ./setup.sh."
    exit 1
  fi
fi

PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
log "Verified Python ${PY_VER}"

if [ "$IS_TERMUX" -eq 1 ]; then
  if [ ! -w "/sdcard" ]; then
    log "Requesting Termux shared storage permission for /sdcard/.zerorcmemo..."
    termux-setup-storage || true
  fi
  pip install --upgrade pip
  pip install -r requirements.txt
  pip install -e . --no-build-isolation --no-deps
  PY_BIN="python3"
else
  if [ ! -d ".venv" ]; then
    log "Creating isolated virtual environment (.venv)..."
    python3 -m venv .venv
  fi
  PY_BIN=".venv/bin/python3"
  "$PY_BIN" -m pip install --upgrade pip
  "$PY_BIN" -m pip install -r requirements.txt
  "$PY_BIN" -m pip install -e . --no-build-isolation --no-deps
fi

MODEL_MODE="${ZERO_MODEL_MODE:-}"
if [ -z "$MODEL_MODE" ]; then
  printf "%bSelect EmbeddingGemma 2 backend:%b\\n" "$ACID" "$RESET"
  printf "  %b1%b) Ollama local (embeddinggemma-2:270m — recommended for CPU/VPS/laptop)\\n" "$ACID" "$RESET"
  printf "  %b2%b) Hugging Face sentence-transformers (google/embeddinggemma-2 text-only core)\\n" "$ACID" "$RESET"
  printf "  %b3%b) Lightweight local semantic fallback (256d MRL, zero extra downloads — ideal for mobile/Termux)\\n" "$ACID" "$RESET"
  read -r -p "Choice [1/2/3] (default 3): " MODEL_MODE || MODEL_MODE="3"
  MODEL_MODE="${MODEL_MODE:-3}"
fi

case "$MODEL_MODE" in
  1|ollama)
    if ! command -v ollama >/dev/null 2>&1; then
      if [ "$IS_TERMUX" -eq 1 ]; then
        warn "Ollama native binary is not bundled in Termux. Run Ollama on a LAN host and pass --ollama-url, or use mode 3."
      else
        log "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
      fi
    fi
    if command -v ollama >/dev/null 2>&1; then
      log "Pulling EmbeddingGemma 2 (embeddinggemma-2:270m)..."
      ollama pull embeddinggemma-2:270m || warn "Start 'ollama serve' and run 'ollama pull embeddinggemma-2:270m'."
    fi
    ;;
  2|hf|st)
    log "Installing Hugging Face sentence-transformers stack for google/embeddinggemma-2..."
    "$PY_BIN" -m pip install -r requirements-eg2.txt
    "$PY_BIN" -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('google/embeddinggemma-2', config_kwargs={'vision_config': None, 'audio_config': None}); print('EG2_HF_READY')" || warn "Authenticate with 'huggingface-cli login' if gated, then re-run."
    ;;
  *)
    log "Configured zero-dependency 256d local semantic fallback."
    ;;
esac

log "Running Zero Suite health verification..."
"$PY_BIN" Zero-Suite.py --memory-status --accept-policy
log "Setup complete. Launch via: ${PY_BIN} Zero-Suite.py"
