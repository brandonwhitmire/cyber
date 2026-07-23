+++
title = "tmux"
+++

- [Ippsec Tmux Video Tutorial](https://www.youtube.com/watch?v=Lqehvpe_djs)
- [Ippsec Tmux Cheat Sheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/)
- https://tmuxcheatsheet.com/

## Setup

Install [Tmux Plugin Manager (TPM)](https://github.com/tmux-plugins/tpm):

```bash
sudo apt install -y tmux xclip
mkdir -p ~/my_data/
cat > ~/.tmux.conf <<'EOF'
set -g history-limit 50000
set -g mouse on
set -g @logs_dir "$HOME/my_data/tmux_logs"
run-shell 'mkdir -p "#{@logs_dir}"'
set-hook -g after-new-session 'pipe-pane -o "cat >> #{@logs_dir}/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set-hook -g after-new-window 'pipe-pane -o "cat >> #{@logs_dir}/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set-hook -g after-split-window 'pipe-pane -o "cat >> #{@logs_dir}/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set-hook -g session-created 'run-shell "tmux list-panes -s -F \"#{pane_id}\" | xargs -I{} tmux pipe-pane -t {} -o \"cat >> #{@logs_dir}/$(date +%Y%m%d-%H%M%S)-restored-{}.log\""'
set-hook -g client-detached 'run-shell ~/.tmux/plugins/tmux-resurrect/scripts/save.sh'
set-hook -g session-closed 'run-shell ~/.tmux/plugins/tmux-resurrect/scripts/save.sh'
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-sessionist'
set -g @plugin 'tmux-plugins/tmux-pain-control'
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-yank'
set -g @plugin 'sainnhe/tmux-fzf'
set -g @plugin 'christoomey/vim-tmux-navigator'
set -g @plugin 'catppuccin/tmux'
set -g @catppuccin_flavour 'mocha'
set -g @catppuccin_window_status_style "rounded"
set -g @resurrect-capture-pane-contents 'on'
set -g status-right "#{E:@catppuccin_status_session} #{E:@catppuccin_status_host}"
run '~/.tmux/plugins/tpm/tpm'
EOF
[ ! -d ~/.tmux/plugins/tpm ] && git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
export TMUX_PLUGIN_MANAGER_PATH="$HOME/.tmux/plugins/"
tmux start-server
tmux new-session -d -s pentest-engagement
$TMUX_PLUGIN_MANAGER_PATH/tpm/bin/install_plugins
tmux kill-server
printf '\n[ -z "$TMUX" ] && tmux new-session -A -s pentest-engagement\n' >> ~/.bashrc
printf '\n[ -z "$TMUX" ] && tmux new-session -A -s pentest-engagement\n' >> ~/.zshrc
```

## Tmux Core Hotkeys

*Default Prefix: `CTRL+B`*

| Action                      | Hotkey               | Description                                     |
| :-------------------------- | :------------------- | :---------------------------------------------- |
| **Create New Tab (Window)** | `Prefix` + `C`       | Creates a new tmux window (full-screen tab).    |
| **Next Tab**                | `Prefix` + `N`       | Switches to the next tmux window.               |
| **Previous Tab**            | `Prefix` + `P`       | Switches to the previous tmux window.           |
| **Switch by Number**        | `Prefix` + `0-9`     | Jumps directly to a window by index.            |
| **Rename Current Tab**      | `Prefix` + `,`       | Renames the current window for easier tracking. |
| **Search Output**           | `Prefix` + `[` + `/` | Search for words within the terminal output.    |

## [Tmux Logging](https://github.com/tmux-plugins/tmux-logging) Hotkeys

*Note: Logging is enabled by default in this config via `pipe-pane`, with one timestamped file per pane in `~/.tmux/logs/` (format: `YYYYmmdd-HHMMSS-session-window-pane.log`). The plugin hotkeys below are still useful for manual/retroactive captures. See docs for [changing plugin logging options](https://github.com/tmux-plugins/tmux-logging/blob/master/docs/configuration.md).*

| Action | Hotkey | Description |
| :--- | :--- | :--- |
| **Toggle Logging** | `Prefix` + `Shift` + `P` | Starts/stops logging the current pane to a file. |
| **Retroactive Log** | `Prefix` + `Alt` + `Shift` + `P` | Saves the entire pane history (up to `history-limit`) if you forgot to start logging initially. |
| **Pane Capture** | `Prefix` + `Alt` + `P` | Saves only the *currently visible* screen. Solves copy/paste formatting messes when panes are split. |
