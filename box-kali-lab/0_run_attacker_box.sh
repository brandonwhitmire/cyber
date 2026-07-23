#!/bin/bash
# This script starts the Kali Linux box VM and opens an SSH session.
# It checks if the gold image snapshot exists before proceeding.
#
# USAGE:
#   ./0_run_attacker_box.sh

set -e

# --- Load shared configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/5_config"

# --- Check if gold image snapshot exists ---
echo "[*] Checking for gold image snapshot '$SNAPSHOT_NAME'..."
if snapshot_exists; then
  echo "[+] Gold image snapshot found. Starting VM and opening SSH session..."
  echo
  source .venv/bin/activate && vagrant up && vagrant ssh
else
  echo "[!] Gold image snapshot '$SNAPSHOT_NAME' not found!"
  echo
  echo "    -> Please create the gold image snapshot first by running:"
  echo "       ./1_create_gold_image.sh"
  echo
  echo "    This will provision the VM and create a clean snapshot for future use."
  exit 1
fi

