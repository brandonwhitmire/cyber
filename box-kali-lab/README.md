# Kali Linux Lab

An automated Kali Linux, pentesting-focused lab environment provisioned with Ansible and managed via Vagrant.

## Prerequisites

- Python 3
- Vagrant
- libvirt (for KVM provider)

## Setup

1. **Install dependencies:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip3 install --requirement requirements.txt
   ansible-galaxy collection install --requirements-file requirements.yml
   ```

2. **Quick Usage:**

   ```bash
   ./0_run_attack_box.sh
   ```

## Snapshot Management

The project includes helper scripts for managing VM snapshots:

- `0_run_attack_box.sh` - Starts the VM and opens an SSH session. Requires the gold image snapshot to exist.
- `1_create_gold_image.sh` - Creates a gold image snapshot after provisioning. **Run this first** to save a clean state after initial setup. Run `vagrant box update` to update Kali base box.
- `2_restore_to_gold.sh` - Restores the VM to the gold image snapshot, discarding all current changes.
- `3_retake_gold.sh` - Retakes the gold image snapshot from the current VM state, useful for updating the baseline.

All scripts support `-f` or `--force` flags for non-interactive mode. The snapshot name and shared functions are configured in `5_config`.

To manually check for snapshots like "gold_image", use:
```bash
vagrant snapshot list
```
