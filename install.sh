#!/usr/bin/env bash
# BEGIN FILETRUST INSTALL BANNER — from root singature.txt
filetrust_install_banner() {
  local banner_dir banner_version='unknown' banner_line
  banner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -r "$banner_dir/VERSION" ]]; then
    IFS= read -r banner_version < "$banner_dir/VERSION" || [[ -n $banner_version ]]
    banner_version=${banner_version%$'\r'}
  fi
  cat <<'FILETRUST_BANNER_TOP'
███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝


Author: Ali Farahpoor
Company: Electra Sphere Innovations (ElectraSI.es)
Location: Barcelona, Spain
Contact: support@filetrust.io

FILETRUST_BANNER_TOP
  printf 'Version: %s %s\n' 'Guardians' "$banner_version"
  cat <<'FILETRUST_BANNER_BOTTOM'
Release Date: 26 October 2026

Documentation: https://docs.filetrust.io
Website: https://www.filetrust.io
FILETRUST_BANNER_BOTTOM
  printf '\n'
}
filetrust_install_banner
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
set +x
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'The packaged ZoKrates runtime requires Linux x86_64.' >&2
  exit 1
fi
if [[ ! -f "$source_dir/runtime/start.py" ]]; then
  echo 'Incomplete Guardian package: runtime/start.py is missing. Clone the complete repository or extract the full installer ZIP.' >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo 'Run sudo bash install.sh for the dedicated user and reboot service.' >&2
  exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
  echo 'The automatic server installer requires a running systemd system.' >&2
  exit 1
fi
# Reject command output accidentally exported as a token before installing
# packages, and never echo that output back into a requests exception.
if command -v python3 >/dev/null; then
  python3 "$source_dir/github_auth.py" --check
fi
echo '[Setup] Installing Python, venv support, and HTTPS certificates'
if ! command -v apt-get >/dev/null; then
  echo 'Automatic dependency installation currently supports Debian/Ubuntu.' >&2
  exit 1
fi
apt-get update
apt-get install -y python3 python3-venv ca-certificates libstdc++6 libgcc-s1 util-linux
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  echo 'Python 3.10 or newer is required. Use Debian 12+/Ubuntu 22.04+.' >&2
  exit 1
fi
app_dir=/opt/filetrust-guardian
install -d -m 0755 "$app_dir"
if systemctl is-active --quiet filetrust-guardian.service; then
  echo 'A Guardian is running. Stop it before updating the installer; existing state is retained.' >&2
  exit 1
fi
install -d -m 0755 "$app_dir/.filetrust-updates"
touch "$app_dir/.filetrust-updates/update.lock" "$app_dir/.filetrust-updates/run.lock"
chmod 0644 "$app_dir/.filetrust-updates/update.lock" "$app_dir/.filetrust-updates/run.lock"
exec 9< "$app_dir/.filetrust-updates/update.lock"
flock -n 9 || { echo 'Another update/installation is running.' >&2; exit 1; }
exec 8< "$app_dir/.filetrust-updates/run.lock"
flock -n 8 || { echo 'A Guardian process is still using this application.' >&2; exit 1; }
for name in guardian.py github_auth.py artifact_store.py network.py recovery_install.py network-config.py ft_network_config.py ft_network_http.py network_config_policy.py uninstall.py update.py ft_updates.py upgrade.py ft_update_install.py ft_update_bootstrap.py ft_update_service.py VERSION update-root.json update-source.json requirements.txt release-key.pub README.md LICENSE THIRD-PARTY-NOTICES.md; do
  if [[ "$source_dir/$name" != "$app_dir/$name" ]]; then
    install -m 0644 "$source_dir/$name" "$app_dir/$name"
  fi
done
if [[ "$source_dir" != "$app_dir" ]]; then
  cp -a "$source_dir/runtime" "$app_dir/"
  cp -a "$source_dir/licenses" "$app_dir/"
fi
echo '[Setup] Installing the pinned Guardian Python dependencies'
python3 -c 'import sys; sys.path.insert(0, "/opt/filetrust-guardian"); from ft_update_bootstrap import initialize; initialize("/opt/filetrust-guardian")'
python3 -m venv "$app_dir/.venv"
"$app_dir/.venv/bin/python" -m pip install --disable-pip-version-check -r "$app_dir/requirements.txt"
# Reuse the installer's already-held application lock after exec. Opening a
# second flock here would wait on our own exclusive lock forever.
export FILETRUST_RUN_LOCK_FD=8
exec "$app_dir/.venv/bin/python" "$app_dir/guardian.py" install --service "$@"
