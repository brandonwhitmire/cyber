#!/bin/bash

# Script to update artifacts and tools
# This script is called by the GitHub Actions workflow on a weekly schedule

set -euo pipefail

# Define the directory where repositories and scripts will be stored
# Default to ../tools (one directory above where this script is located)
TOOLS_DIR="${TOOLS_DIR:-../tools}"

# List of repositories to clone/update
# Format: repo_url:branch (branch is optional, defaults to master/main)
REPOS=(
  "https://github.com/andrew-d/static-binaries.git:master"
)

# List of scripts/files to download
# Format: url (files will be saved to TOOLS_DIR with their original filename)
SCRIPTS=(
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
  "https://github.com/peass-ng/PEASS-ng/raw/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
  "https://github.com/peass-ng/PEASS-ng/releases/download/20251101-a416400b/winPEASx86.exe"
)

echo "=== Starting artifact update process ==="

# Create tools directory if it doesn't exist
mkdir -p "$TOOLS_DIR"

# Function to extract repository name from URL
get_repo_name() {
  local repo_url="$1"
  basename "$repo_url" .git
}

# Function to clone or update a repository
update_repo() {
  local repo_spec="$1"
  local repo_url branch
  
  # Split by last colon to get repo URL and branch (URLs contain colons like https://)
  if [[ "$repo_spec" == *":"* ]]; then
    # Use parameter expansion to split on the last colon
    repo_url="${repo_spec%:*}"
    branch="${repo_spec##*:}"
  else
    repo_url="$repo_spec"
    branch="master"
  fi
  
  local repo_name=$(get_repo_name "$repo_url")
  local repo_path="$TOOLS_DIR/$repo_name"
  
  echo "Processing repository: $repo_name"
  
  if [ -d "$repo_path" ]; then
    echo "  Repository exists, updating..."
    cd "$repo_path"
    # Check if it's a shallow clone and unshallow if needed
    if [ -f ".git/shallow" ]; then
      git fetch --unshallow 2>/dev/null || git fetch --all
    else
      git fetch --all
    fi
    git checkout "$branch" 2>/dev/null || git checkout -b "$branch" "origin/$branch" 2>/dev/null || git checkout master
    git pull origin "$branch" || git pull origin master || true
    cd - > /dev/null
  else
    echo "=== Cloning repository ==="
    git clone --branch "$branch" --single-branch --depth 1 "$repo_url" "$repo_path" || \
    git clone --branch master --single-branch --depth 1 "$repo_url" "$repo_path" || \
    git clone --single-branch --depth 1 "$repo_url" "$repo_path"
  fi
  
  echo "  ✓ $repo_name updated"
}

# Function to download a script/file
download_script() {
  local script_spec="$1"
  local url dest_path dest_dir
  
  # Check if a custom destination path is specified (format: url:destination_path)
  # URLs contain colons (https://), so we need to distinguish between:
  # - URL with protocol (https://example.com/file) - no custom path
  # - URL with custom path (https://example.com/file:/custom/path) - has custom path
  # For URLs, we look for a colon that comes AFTER the protocol (after ://)
  if [[ "$script_spec" =~ ^https?:// ]]; then
    # This is a URL - check if there's a colon after the :// part
    local after_protocol="${script_spec#*://}"
    # Check if there's a colon in the path part (not in the protocol)
    if [[ "$after_protocol" == *":"* ]]; then
      # There's a colon after the protocol, check if what follows looks like a path
      local after_last_colon="${script_spec##*:}"
      # If it starts with //, it's part of the URL protocol, not a custom path
      # If it starts with a single / (not //), ./, or ~, it's likely a custom path
      if [[ "$after_last_colon" =~ ^[.~] ]] || [[ "$after_last_colon" =~ ^/[^/] ]]; then
        # Custom destination path specified (starts with /, ./, or ~, but not //)
        url="${script_spec%:*}"
        dest_path="${script_spec##*:}"
        local full_dest="$dest_path"
        dest_dir=$(dirname "$full_dest")
      else
        # No custom path (starts with // or something else), use the URL's filename
        url="$script_spec"
        dest_path=$(basename "$url")
        local full_dest="$TOOLS_DIR/$dest_path"
        dest_dir="$TOOLS_DIR"
      fi
    else
      # No colon after protocol, no custom path
      url="$script_spec"
      dest_path=$(basename "$url")
      local full_dest="$TOOLS_DIR/$dest_path"
      dest_dir="$TOOLS_DIR"
    fi
  elif [[ "$script_spec" == *":"* ]] && [[ "${script_spec##*:}" =~ ^[/.~] ]]; then
    # Not a URL, but has a colon and the part after looks like a path
    url="${script_spec%:*}"
    dest_path="${script_spec##*:}"
    local full_dest="$dest_path"
    dest_dir=$(dirname "$full_dest")
  else
    # No custom path, use the URL's filename
    url="$script_spec"
    dest_path=$(basename "$url")
    local full_dest="$TOOLS_DIR/$dest_path"
    dest_dir="$TOOLS_DIR"
  fi
  
  echo "=== Downloading script: $(basename "$full_dest") ==="
  
  # Create destination directory if it doesn't exist
  mkdir -p "$dest_dir"
  
  # Download the file
  wget -q --show-progress -O "$full_dest" "$url" || {
    echo "  ✗ Failed to download $url"
    return 1
  }
  
  # Make it executable if it's a shell script, batch file, PowerShell script, or executable
  if [[ "$full_dest" == *.sh ]] || [[ "$full_dest" == *.bat ]] || [[ "$full_dest" == *.ps1 ]] || [[ "$full_dest" == *.exe ]]; then
    chmod +x "$full_dest"
  fi
  
  echo "  ✓ $(basename "$full_dest") downloaded to $dest_path"
}

# Update each repository
for repo in "${REPOS[@]}"; do
  update_repo "$repo"
done

# Download each script
for script in "${SCRIPTS[@]}"; do
  download_script "$script"
done

echo "✓ Artifact update process completed..."
