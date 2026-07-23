#!/usr/bin/env python3
"""
Script to add front matter to lab markdown files that don't have it.
This ensures all lab files have proper front matter for Hugo to render them correctly.
"""

import os
import sys
import re
from pathlib import Path


def has_front_matter(content):
    """Check if markdown file already has front matter (TOML or YAML)."""
    content = content.strip()
    return content.startswith('+++') or content.startswith('---')


def extract_front_matter(content):
    """Extract existing front matter if present."""
    if not has_front_matter(content):
        return None, content
    
    delimiter = '+++' if content.startswith('+++') else '---'
    lines = content.split('\n')
    
    if lines[0].strip() != delimiter:
        return None, content
    
    front_matter_lines = []
    content_lines = []
    in_front_matter = True
    delimiter_count = 0
    
    for line in lines[1:]:
        if in_front_matter:
            if line.strip() == delimiter:
                delimiter_count += 1
                if delimiter_count == 1:  # Found closing delimiter
                    in_front_matter = False
                    continue
            if delimiter_count == 0:
                front_matter_lines.append(line)
        else:
            content_lines.append(line)
    
    front_matter = '\n'.join(front_matter_lines) if front_matter_lines else None
    body = '\n'.join(content_lines) if content_lines else content
    
    return front_matter, body


def add_front_matter(filepath, dry_run=False):
    """Add front matter to a markdown file if it doesn't have any."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return False
    
    # Skip _index.md files
    if os.path.basename(filepath) == '_index.md':
        return False
    
    # Check if front matter already exists
    if has_front_matter(content):
        return False
    
    # Extract filename without extension for title
    basename = os.path.basename(filepath)
    title = os.path.splitext(basename)[0]
    
    # Add front matter
    front_matter = f"+++\ntitle = \"{title}\"\n+++\n"
    
    # Preserve any leading newlines in original content
    if content and not content.startswith('\n'):
        new_content = front_matter + content
    else:
        new_content = front_matter + '\n' + content.lstrip('\n')
    
    if dry_run:
        print(f"[DRY RUN] Would add front matter to: {filepath}")
        return True
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"✓ Added front matter to: {os.path.basename(filepath)}")
        return True
    except Exception as e:
        print(f"Error writing {filepath}: {e}", file=sys.stderr)
        return False


def process_lab_directories(directories, dry_run=False):
    """Process all markdown files in the specified lab directories."""
    added_count = 0
    processed_count = 0
    
    for directory in directories:
        if not os.path.isdir(directory):
            print(f"Warning: Directory not found: {directory}", file=sys.stderr)
            continue
        
        for filename in os.listdir(directory):
            if not filename.endswith('.md'):
                continue
            
            filepath = os.path.join(directory, filename)
            if not os.path.isfile(filepath):
                continue
            
            processed_count += 1
            if add_front_matter(filepath, dry_run):
                added_count += 1
    
    return added_count, processed_count


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Add front matter to lab markdown files that don\'t have it.'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without making changes'
    )
    parser.add_argument(
        '--dirs',
        nargs='+',
        default=[
            'content/Labs - TryHackMe',
            'content/Labs - HackTheBox'
        ],
        help='Directories to process (default: content/Labs - TryHackMe content/Labs - HackTheBox)'
    )
    
    args = parser.parse_args()
    
    # Get script directory and resolve paths relative to repo root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)  # Go up one level from scripts/
    
    # Resolve directories relative to repo root
    directories = [os.path.join(repo_root, d) for d in args.dirs]
    
    print(f"Processing lab directories...")
    if args.dry_run:
        print("(DRY RUN mode - no files will be modified)")
    
    added_count, processed_count = process_lab_directories(directories, args.dry_run)
    
    if args.dry_run:
        print(f"\n[DRY RUN] Would add front matter to {added_count} files (processed {processed_count} total)")
    else:
        print(f"\n✓ Added front matter to {added_count} files (processed {processed_count} total)")
    
    return 0 if added_count == 0 or not args.dry_run else 1


if __name__ == '__main__':
    sys.exit(main())

