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
  return 1
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

container_running() {
  local name="$1"
  docker ps --format '{{.Names}}' | grep -qx "$name"
}

do_start() {
  local name
  name="$(find_container || true)"
  if [[ -n "$name" ]]; then
    if container_running "$name"; then
      echo "[INFO] container already running: $name"
      return
    fi
    echo "[INFO] starting container: $name"
    docker start "$name"
    return
  fi

  local cc
  cc="$(compose_cmd || true)"
  if [[ -n "$cc" ]] && [[ -f "$COMPOSE_FILE" ]]; then
    echo "[INFO] starting via compose service: $SERVICE_NAME"
    (cd "$ROOT_DIR" && $cc up -d "$SERVICE_NAME")
    return
  fi

  echo "[ERROR] no known container found and compose unavailable" >&2
  exit 1
}

do_stop() {
  local name
  name="$(find_container || true)"
  if [[ -n "$name" ]]; then
    if container_running "$name"; then
      echo "[INFO] stopping container: $name"
      docker stop "$name"
    else
      echo "[INFO] container already stopped: $name"
    fi
    return
  fi

  local cc
  cc="$(compose_cmd || true)"
  if [[ -n "$cc" ]] && [[ -f "$COMPOSE_FILE" ]]; then
    echo "[INFO] stopping via compose service: $SERVICE_NAME"
    (cd "$ROOT_DIR" && $cc stop "$SERVICE_NAME")
    return
  fi

  echo "[ERROR] no known container found and compose unavailable" >&2
  exit 1
}

do_restart() {
  local name
  name="$(find_container || true)"
  if [[ -n "$name" ]]; then
    echo "[INFO] restarting container: $name"
    docker restart "$name"
    return
  fi

  local cc
  cc="$(compose_cmd || true)"
  if [[ -n "$cc" ]] && [[ -f "$COMPOSE_FILE" ]]; then
    echo "[INFO] restarting via compose service: $SERVICE_NAME"
    (cd "$ROOT_DIR" && $cc restart "$SERVICE_NAME")
    return
  fi

  echo "[ERROR] no known container found and compose unavailable" >&2
  exit 1
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
