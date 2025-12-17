#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

if [[ "$OSTYPE" == "darwin"* ]]; then
    export LC_ALL=C
    export LANG=C
    export LC_CTYPE=C
fi

info() { printf "[info] %s\n" "$*"; }
warn() { printf "[warn] %s\n" "$*"; }
err() { printf "[error] %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }
clear_scr() { clear 2>/dev/null || true; printf '\e[3J' 2>/dev/null || true; }

if xargs -r </dev/null echo >/dev/null 2>&1; then
    xargs_r='-r'
else
    xargs_r=''
fi
export xargs_r

# Docker must be usable without sudo on Linux (docker group required).
# Keep SUDO exported for backward compatibility (always empty).
SUDO=""
export SUDO
DOCKER_OK=0

require_docker_access() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            clear_scr
            err "Docker is not installed."
            info "hint: Install Docker Desktop, launch it, then re-run this script."
            exit 1
        fi

        if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
            local sock
            sock="${DOCKER_HOST#unix://}"
            if [[ ! -S "$sock" ]]; then
                clear_scr
                err  "DOCKER_HOST points to '$sock', but that socket does not exist."
                info "hint: Start Docker Desktop, or run: unset DOCKER_HOST ; docker context use default"
                exit 1
            fi
        fi

        if ! docker info >/dev/null 2>&1; then
            clear_scr
            err  "Docker is installed but not running."
            info "hint: Open 'Docker.app' and wait until the whale icon stops animating, then re-run this script."
            info "hint: If you use custom contexts, try: unset DOCKER_HOST ; docker context use default"
            exit 1
        fi

        DOCKER_OK=1
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        clear_scr
        err "Docker is not installed."
        info "hint: install docker, then re-run this script."
        exit 1
    fi

    # Linux: require docker group membership; do not call docker if not in group (avoid permission spam).
    if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
        clear_scr
        err "Your user is not in the 'docker' group."
        info "Please add your user to the docker group to run docker without sudo (and avoid root-owned bind mounts)."
        echo
        echo "Paste these commands into your terminal:"
        echo
        echo "sudo groupadd docker 2>/dev/null || true"
        echo "sudo usermod -aG docker \$USER"
        echo
        info "Then close this terminal and open a new one (or run: newgrp docker), and run this script again."
        exit 1
    fi

    # Must work without sudo, but keep stderr quiet.
    if ! docker info >/dev/null 2>&1; then
        clear_scr
        err "Docker is installed but not accessible without sudo."
        info "hint: start docker daemon (systemd): sudo systemctl enable --now docker"
        info "hint: if you just added yourself to the docker group, re-login or run: newgrp docker"
        exit 1
    fi

    DOCKER_OK=1
    return 0
}

declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image() { _tmp_images+=("$1"); }

__compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        err "docker compose is not available."
        return 1
    fi
}

prune_build_caches() {
    docker builder prune -af >/dev/null 2>&1 || true

    if docker buildx ls >/dev/null 2>&1; then
        if docker buildx ls --format '{{.Name}}' >/dev/null 2>&1; then
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(docker buildx ls --format '{{.Name}}')
        else
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(docker buildx ls | awk 'NR>1{print $1}')
        fi
    fi
}

preclean_patterns() {
    for name in exit_a exit_b haproxy support; do
        docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} docker rm -f >/dev/null 2>&1 || true
    done
    local nets=()
    [[ -n "${ext_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$ext_network_container_subnet_cidr_ipv4" )
    [[ -n "${int_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$int_network_container_subnet_cidr_ipv4" )
    docker network ls -q | while read -r nid; do
        subnets=$(docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
        for net in "${nets[@]}"; do
            if echo "$subnets" | grep -qw -- "$net"; then
                docker network rm "$nid" >/dev/null 2>&1 || true
                break
            fi
        done
    done
    prune_build_caches
}

cleanup_project() {
    local proj="$1"
    local yml="$2"

    if [[ -f "$yml" ]]; then
        __compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy deploy; do
        docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} docker rm -f >/dev/null 2>&1 || true
    done

    docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} docker volume rm -f >/dev/null 2>&1 || true
    if [[ -z "$(docker ps -aq --filter ancestor=debian:trixie-slim 2>/dev/null || true)" ]]; then
        docker rmi -f debian:trixie-slim >/dev/null 2>&1 || true
    fi
}

guard_pid=""

start_session_guard() {
    local proj="$1"
    local yml="$2"
    local parent="$$"
    local tty_path
    tty_path="${SSH_TTY:-$(tty 2>/dev/null || echo)}"
    mkdir -p "${tmp_folder}/${proj}"
    local guard="${tmp_folder}/${proj}/._guard.sh"
    local pidfile="${tmp_folder}/${proj}/._guard.pid"

    cat >"$guard" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail

proj="$1"
yml="$2"
parent="$3"
tty_path="$4"

on_term() {
    if [[ -f "$yml" ]]; then
        docker compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy deploy; do
        docker ps -aq -f "name=^${name}$" | xargs ${xargs_r:-} docker rm -f >/dev/null 2>&1 || true
    done

    docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} docker volume rm -f >/dev/null 2>&1 || true

    exit 0
}

trap on_term INT TERM HUP

while :; do
    kill -0 "$parent" 2>/dev/null || break
    if [[ -n "$tty_path" && ! -e "$tty_path" ]]; then
        break
    fi
    sleep 1
done

on_term
EOS

    chmod +x "$guard"

    if command -v setsid >/dev/null 2>&1; then
        (
            setsid -w bash "$guard" "$proj" "$yml" "$parent" "$tty_path" >/dev/null 2>&1 &
            echo $! > "$pidfile"
        )
    else
        (
            nohup bash "$guard" "$proj" "$yml" "$parent" "$tty_path" >/dev/null 2>&1 &
            echo $! > "$pidfile"
        )
    fi

    guard_pid="$(cat "$pidfile" 2>/dev/null || true)"
}

stop_session_guard() {
    local pid="${guard_pid:-}"

    if [[ -z "$pid" ]]; then
        local pf
        pf="$(find "${tmp_folder}" -maxdepth 3 -name '._guard.pid' 2>/dev/null | head -n1 || true)"
        [[ -n "$pf" ]] && pid="$(cat "$pf" 2>/dev/null || true)"
    fi

    [[ -z "$pid" ]] && return 0

    kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || { unset guard_pid; return 0; }
        sleep 0.2
    done
    kill -KILL "$pid" 2>/dev/null || true
    unset guard_pid
}

cleanup_all() {
    set +e

    stop_session_guard

    # If docker is not accessible, do not call docker at all (avoids permission spam).
    if [[ "${DOCKER_OK:-0}" == "1" ]]; then
        cleanup_project "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
    fi

    local f d
    if [[ ${_tmp_files+x} ]]; then
        for f in "${_tmp_files[@]}"; do
            [[ -n "$f" ]] && rm -f "$f" 2>/dev/null || true
        done
    fi
    if [[ ${_tmp_dirs+x} ]]; then
        for d in "${_tmp_dirs[@]}"; do
            [[ -n "$d" ]] && rm -rf "$d" 2>/dev/null || true
        done
    fi

    rm -rf -- "${tmp_folder:-}" 2>/dev/null || true

    if [[ "${DOCKER_OK:-0}" == "1" ]]; then
        prune_build_caches

        if [[ "${STRICT_CLEANUP:-0}" == "1" ]]; then
            warn "Performing system-wide prune (--all --volumes)."
            docker system prune -af --volumes >/dev/null 2>&1 || true
        fi
    fi

    set -e
}

check_pkg() {
    local os=""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "Docker on macOS is ready."
        return 0
    fi

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os="$ID"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        case "$os" in
            debian)
                [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "installing docker (Debian)…"
                sudo install -d -m 0755 -o root -g root /etc/apt/keyrings
                local arch codename
                arch="$(dpkg --print-architecture)"
                codename="$(lsb_release -cs 2>/dev/null || true)"
                : "${codename:=stable}"
                curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
                sudo sh -c "printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.gpg\n' '$codename' '$arch' > /etc/apt/sources.list.d/docker.sources"
                sudo sh -c "printf 'Package: *\nPin: origin download.docker.com\nPin-Priority: 900\n' > /etc/apt/preferences.d/docker"
                sudo apt-get update >/dev/null 2>&1
                sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1
                ;;
            arch|manjaro)
                [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "installing docker (Arch/Manjaro)…"
                sudo pacman -Sy --needed --noconfirm docker docker-compose >/dev/null 2>&1
                ;;
            *)
                warn "unsupported distro '$os' – install docker manually."
                return 1
                ;;
        esac
    else
        [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "docker is present."
    fi

    if command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service' ); then
        sudo systemctl enable --now docker 2>/dev/null || true
    fi
}

run_build_proxy() {
    local proj_dir="${tmp_folder}/${rnd_proj_name}"
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit_a,exit_b,haproxy,deploy}

    local host_uid host_gid
    host_uid="$(id -u)"
    host_gid="$(id -g)"

cat <<EOF > "${tmp_folder}/${rnd_proj_name}/.env"
int_network_container_subnet_cidr_ipv4="$int_network_container_subnet_cidr_ipv4"
int_network_container_gateway_ipv4="$int_network_container_gateway_ipv4"
int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
int_network_container_deploy_ipv4="${int_network_container_deploy_ipv4}"
ext_network_container_subnet_cidr_ipv4="$ext_network_container_subnet_cidr_ipv4"
ext_network_container_gateway_ipv4="$ext_network_container_gateway_ipv4"
ext_network_container_exit_a_ipv4="$ext_network_container_exit_a_ipv4"
ext_network_container_exit_b_ipv4="$ext_network_container_exit_b_ipv4"
tor_ctrl_pass="${tor_ctrl_pass}"
tor_ctrl_hash="${tor_ctrl_hash}"
HOST_UID="${host_uid}"
HOST_GID="${host_gid}"
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
services:
  exit_a:
    container_name: exit_a
    build:
      context: ./exit_a
      dockerfile: Dockerfile
      args:
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
        tor_ctrl_hash: "${tor_ctrl_hash}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      external_network:
        ipv4_address: ${ext_network_container_exit_a_ipv4}
      internal_network:
        ipv4_address: ${int_network_container_exit_a_ipv4}

  exit_b:
    container_name: exit_b
    build:
      context: ./exit_b
      dockerfile: Dockerfile
      args:
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
        tor_ctrl_hash: "${tor_ctrl_hash}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      external_network:
        ipv4_address: ${ext_network_container_exit_b_ipv4}
      internal_network:
        ipv4_address: ${int_network_container_exit_b_ipv4}

  haproxy:
    container_name: haproxy
    build:
      context: ./haproxy
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    restart: always
    logging: { driver: "none" }
    depends_on:
      - exit_a
      - exit_b
    networks:
      internal_network:
        ipv4_address: ${int_network_container_haproxy_ipv4}

  deploy:
    container_name: deploy
    build:
      context: ./deploy
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
    runtime: runc
    volumes:
      - ${HOME}/Downloads/matrix:/home/user/Downloads:ro
    user: "${HOST_UID}:${HOST_GID}"
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      internal_network:
        ipv4_address: ${int_network_container_deploy_ipv4}

networks:
  external_network:
    driver: bridge
    ipam:
      config:
        - subnet: ${ext_network_container_subnet_cidr_ipv4}
          gateway: ${ext_network_container_gateway_ipv4}
  internal_network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${int_network_container_subnet_cidr_ipv4}
          gateway: ${int_network_container_gateway_ipv4}
EOF

    # NOTE:
    # Keep your original Dockerfiles heredocs (exit_a, exit_b, haproxy, deploy) here unchanged.
    # I am not re-pasting them in full in this message to avoid truncation,
    # but NO changes are required there for the docker-group fix.
}

wait_health() {
    local name="$1" timeout="${2:-180}" id hs run i
    for ((i=0; i<timeout; i++)); do
        id="$(docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
        if [[ -n "$id" ]]; then
            hs="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{""}}{{end}}' "$id" 2>/dev/null || true)"
            run="$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)"
            if [[ "$hs" == "healthy" || ( -z "$hs" && "$run" == "true" ) ]]; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

print_health_log() {
    local name="$1" id
    id="$(docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
    [[ -n "$id" ]] || return 0

    docker inspect -f '{{range .State.Health.Log}}{{printf "[%s] code=%d %s\n" .Start .ExitCode .Output}}{{end}}' "$id" 1>&2 || true
}

wait_stack_ready() {
    info "Waiting for exit_a health"
    if ! wait_health exit_a 180; then
        err "exit_a did not become healthy. Health log:"
        print_health_log exit_a
        die "Startup failed"
    fi
    info "Waiting for exit_b health"
    if ! wait_health exit_b 180; then
        err "exit_b did not become healthy. Health log:"
        print_health_log exit_b
        die "Startup failed"
    fi
    info "Waiting for haproxy health"
    if ! wait_health haproxy 180; then
        err "haproxy did not become healthy. Health log:"
        print_health_log haproxy
        die "Startup failed"
    fi
    info "All proxy containers are healthy."
}

ext_network_container_subnet_cidr_ipv4="10.16.85.0/29"
ext_base=${ext_network_container_subnet_cidr_ipv4%/*}
ext_base=${ext_base%.*}.
ext_network_container_gateway_ipv4="${ext_base}1"
ext_network_container_exit_a_ipv4="${ext_base}2"
ext_network_container_exit_b_ipv4="${ext_base}3"

int_network_container_subnet_cidr_ipv4="172.16.85.0/29"
int_base=${int_network_container_subnet_cidr_ipv4%/*}
int_base=${int_base%.*}.
int_network_container_gateway_ipv4="${int_base}1"
int_network_container_exit_a_ipv4="${int_base}2"
int_network_container_exit_b_ipv4="${int_base}3"
int_network_container_haproxy_ipv4="${int_base}4"
int_network_container_deploy_ipv4="${int_base}5"

tmp_folder="$(mktemp -d -t deploystack.XXXXXXXX)"
append_tmp_dir "$tmp_folder"
rnd_proj_name="deploystack_$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"

QUIET_CHECK_PKG=1
check_pkg
require_docker_access

trap 'cleanup_all; exit 130' INT
trap 'cleanup_all' EXIT TERM HUP QUIT

preclean_patterns

tor_ctrl_pass="$(LC_ALL=C tr -dc 'A-Za-z0-9!?+=_' </dev/urandom | head -c 32 || true)"
tor_ctrl_hash="$(
    docker run --rm debian:trixie-slim bash -ceu '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends tor >/dev/null
        tor --hash-password "'"$tor_ctrl_pass"'"
    ' | tail -n 1
)"

run_build_proxy
__compose -p "${rnd_proj_name}" -f "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml" build --no-cache
__compose -p "${rnd_proj_name}" -f "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml" up -d --force-recreate
wait_stack_ready
start_session_guard "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
sleep 2

tty_flag="-i"
if [ -t 1 ]; then
    tty_flag="-it"
fi
clear_scr
docker exec $tty_flag deploy /bin/bash -lc 'exec ./deploy'
