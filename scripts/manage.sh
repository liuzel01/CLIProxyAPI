#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
SERVICE_NAME="cli-proxy-api"
CONTAINER_CANDIDATES=("cliproxyapi" "cli-proxy-api")

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] missing command: $1" >&2; exit 127; }
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi
  echo "[ERROR] neither 'docker compose' nor 'docker-compose' is available" >&2
  exit 127
}

find_container() {
  local c
  for c in "${CONTAINER_CANDIDATES[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

do_start() {
  local cc
  cc="$(compose_cmd)"
  if [[ -f "$COMPOSE_FILE" ]]; then
    (cd "$ROOT_DIR" && $cc up -d "$SERVICE_NAME")
  else
    echo "[WARN] compose file not found, trying docker start"
    local name
    name="$(find_container || true)"
    if [[ -z "$name" ]]; then
      echo "[ERROR] no known container found" >&2
      exit 1
    fi
    docker start "$name"
  fi
}

do_stop() {
  local cc
  cc="$(compose_cmd)"
  if [[ -f "$COMPOSE_FILE" ]]; then
    (cd "$ROOT_DIR" && $cc stop "$SERVICE_NAME")
  else
    local name
    name="$(find_container || true)"
    if [[ -z "$name" ]]; then
      echo "[ERROR] no known container found" >&2
      exit 1
    fi
    docker stop "$name"
  fi
}

do_restart() {
  local name
  name="$(find_container || true)"
  if [[ -n "$name" ]]; then
    docker restart "$name"
    return
  fi
  # fallback to compose restart if container name not found yet
  local cc
  cc="$(compose_cmd)"
  (cd "$ROOT_DIR" && $cc restart "$SERVICE_NAME")
}

do_status() {
  local name
  name="$(find_container || true)"
  if [[ -n "$name" ]]; then
    docker ps -a --filter "name=^/${name}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}'
  else
    echo "[INFO] container not found (checked: ${CONTAINER_CANDIDATES[*]})"
  fi
}

do_logs() {
  local name
  name="$(find_container || true)"
  if [[ -z "$name" ]]; then
    echo "[ERROR] container not found (checked: ${CONTAINER_CANDIDATES[*]})" >&2
    exit 1
  fi
  docker logs --tail 200 -f "$name"
}

main() {
  need_cmd docker
  case "$ACTION" in
    start) do_start ;;
    stop) do_stop ;;
    restart) do_restart ;;
    status) do_status ;;
    logs) do_logs ;;
    *)
      cat <<USAGE
Usage: $(basename "$0") <start|stop|restart|status|logs>
USAGE
      exit 2
      ;;
  esac
}

main "$@"
