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
if [[ ${1:-help} == install ]]; then
  filetrust_install_banner
fi
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
set +x
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command_name=${1:-help}
[[ $# -eq 0 ]] || shift
if [[ $command_name == help || $command_name == --help ]]; then
  echo 'Usage: ./docker.sh install [--profile N:t] [settings] | start | stop | restart | status | logs | doctor | check | network-config [check|apply] | claim-dkg | update | rollback | uninstall [--purge]'
  echo 'Requires Docker Engine and Compose on Linux amd64. Native alternative: sudo bash install.sh'
  exit 0
fi
command -v docker >/dev/null || { echo 'Install Docker Engine and its Compose plugin: https://docs.docker.com/engine/install/' >&2; exit 1; }
docker compose version >/dev/null || { echo 'The Docker Compose plugin is required.' >&2; exit 1; }
daemon_platform=$(docker info --format '{{.OSType}}/{{.Architecture}}') || { echo 'Cannot access Docker. Start Docker and use an account with Docker access (or sudo bash docker.sh).' >&2; exit 1; }
[[ $daemon_platform =~ ^linux/(x86_64|amd64)$ ]] || { echo 'Guardian currently requires a Linux amd64 Docker host.' >&2; exit 1; }
export FILETRUST_DOCKER_PROJECT=${FILETRUST_DOCKER_PROJECT:-filetrust-guardian}
[[ ${#FILETRUST_DOCKER_PROJECT} -le 64 && $FILETRUST_DOCKER_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo 'Invalid Docker project name' >&2; exit 1; }
compose=(docker compose --project-name "$FILETRUST_DOCKER_PROJECT" --project-directory "$root" -f "$root/compose.yaml")
image="filetrust-guardian:$FILETRUST_DOCKER_PROJECT"
previous="$image-previous"
tool_container=''
cleanup() { if [[ -n $tool_container ]]; then docker rm -f "$tool_container" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
build_image() {
  local build_network=${FILETRUST_DOCKER_BUILD_NETWORK:-host}
  [[ $build_network == host || $build_network == default ]] || { echo 'Build network must be host or default.' >&2; return 1; }
  docker build --network "$build_network" --target runtime --tag "$image" "$root"
}
container_id() { "${compose[@]}" ps --all -q node; }
stop_node() {
  local cid; cid=$(container_id)
  if [[ -n $cid ]]; then
    echo 'Stopping Guardian; waiting for active work to finish...'
    docker stop --timeout -1 "$cid" >/dev/null
    [[ $(docker inspect --format '{{.State.Running}}' "$cid") == false ]] || { echo 'Guardian is still running; no data or application was removed.' >&2; return 1; }
  fi
}
require_stopped() {
  local cid; cid=$(container_id)
  [[ -z $cid || $(docker inspect --format '{{.State.Running}}' "$cid") != true ]] || { echo 'Stop this Docker Guardian before running this command.' >&2; exit 1; }
}
run_tool() {
  local token='' result=0 flags=(-i)
  [[ ! -t 0 || ! -t 1 ]] || flags+=(-t)
  # Resolve optional private access without displaying it, passing it in argv,
  # building it into an image, or storing it in Docker's persistent Env.
  if [[ -n ${FILETRUST_GITHUB_TOKEN_FILE:-} ]]; then token=$(cat -- "$FILETRUST_GITHUB_TOKEN_FILE")
  elif command -v python3 >/dev/null; then token=$(python3 "$root/github_auth.py" --print)
  elif [[ -n ${GH_TOKEN:-${GITHUB_TOKEN:-}} ]]; then token=${GH_TOKEN:-$GITHUB_TOKEN}
  elif command -v gh >/dev/null; then token=$(gh auth token 2>/dev/null || gh config get oauth_token --host github.com 2>/dev/null || true)
  fi
  tool_container=$("${compose[@]}" run --detach --no-deps setup idle)
  if [[ -n $token ]]; then
    printf '%s' "$token" | docker exec -i "$tool_container" python /opt/filetrust-guardian/container_cli.py stage-token || { cleanup; return 1; }
    unset token
  fi
  docker exec "${flags[@]}" "$tool_container" python /opt/filetrust-guardian/container_cli.py "$@" || result=$?
  docker rm -f "$tool_container" >/dev/null
  tool_container=''
  return "$result"
}
case "$command_name" in
  install) require_stopped; build_image; run_tool install "$@" ;;
  start) "${compose[@]}" up -d --no-build node ;;
  stop) stop_node ;;
  restart) stop_node; "${compose[@]}" up -d --no-build node ;;
  status) "${compose[@]}" ps --all node ;;
  logs) "${compose[@]}" logs --follow --tail 80 node "$@" ;;
  doctor|check|claim-dkg) run_tool "$command_name" "$@" ;;
  network-config)
    if [[ ${1:-check} != check && ${1:-} != status ]]; then require_stopped; fi
    run_tool network-config "$@" ;;
  update)
    cid=$(container_id); [[ -n $cid ]] || { echo 'Install the Docker Guardian first.' >&2; exit 1; }
    old_image=$(docker inspect --format '{{.Image}}' "$cid")
    was_running=$(docker inspect --format '{{.State.Running}}' "$cid")
    echo 'Building the checked-out source. Review and pull the intended Git release first.'
    build_image
    docker tag "$old_image" "$previous"
    stop_node
    if ! run_tool doctor; then
      if [[ $was_running == true ]]; then docker start "$cid" >/dev/null; fi
      echo 'New image validation failed. Previous container and all data retained.' >&2
      exit 1
    fi
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then "${compose[@]}" up -d --no-build node; fi
    echo 'Application image replaced. Wallet, shares and settings preserved. Previous image: ./docker.sh rollback' ;;
  rollback)
    docker image inspect "$previous" >/dev/null
    cid=$(container_id); was_running=false
    if [[ -n $cid ]]; then was_running=$(docker inspect --format '{{.State.Running}}' "$cid"); fi
    stop_node; docker tag "$previous" "$image"
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then "${compose[@]}" up -d --no-build node; fi
    echo 'Previous application image restored; wallet, shares and settings preserved.' ;;
  uninstall)
    [[ $# -eq 0 || ( $# -eq 1 && $1 == --purge ) ]] || { echo 'Usage: ./docker.sh uninstall [--purge]' >&2; exit 1; }
    if [[ ${1:-} == --purge ]]; then
      [[ -t 0 ]] || { echo 'Purge requires a terminal confirmation.' >&2; exit 1; }
      echo 'This permanently deletes this Docker Guardian wallet, unlock key, shares, proof files and state. Retire duties and back up first.'
      read -r -p 'Type DELETE to remove all Guardian data: ' answer
      [[ $answer == DELETE ]] || { echo 'Cancelled.'; exit 1; }
    fi
    stop_node
    "${compose[@]}" down --timeout -1
    if [[ ${1:-} == --purge ]]; then
      docker volume rm "${FILETRUST_DOCKER_PROJECT}_state" "${FILETRUST_DOCKER_PROJECT}_credentials"
      echo 'Docker Guardian and all managed node data removed.'
    else echo 'Docker Guardian removed; wallet, shares and settings kept for reinstall.'; fi
    echo 'Source clone, build images and native Guardian installation are kept.' ;;
  *) echo "Unknown command: $command_name" >&2; exit 1 ;;
esac
