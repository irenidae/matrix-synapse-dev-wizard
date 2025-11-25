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

SUDO=""

if [[ "$OSTYPE" == "darwin"* ]]; then
    info "macOS detected."
    if ! command -v docker >/dev/null 2>&1; then
        err "Docker is not installed."
        info "hint: Install Docker Desktop, launch it, then re-run this script."
        exit 1
    fi

    if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
        sock="${DOCKER_HOST#unix://}"
        if [[ ! -S "$sock" ]]; then
            err  "DOCKER_HOST points to '$sock', but that socket does not exist."
            info "hint: Start Docker Desktop, or run: unset DOCKER_HOST ; docker context use default"
            exit 1
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        err  "Docker is installed but not running."
        info "hint: Open 'Docker.app' and wait until the whale icon stops animating, then re-run this script."
        info "hint: If you use custom contexts, try: unset DOCKER_HOST ; docker context use default"
        exit 1
    fi

    SUDO=""
    info "Docker Desktop is running."
else
    if docker ps >/dev/null 2>&1; then
        SUDO=""
        info "docker is usable without sudo."
    else
        if command -v sudo >/dev/null 2>&1; then
            if sudo -n true 2>/dev/null; then
                SUDO="sudo"
                info "using passwordless sudo for docker."
            else
                if [[ -t 0 && -t 1 ]]; then
                    info "asking for sudo password to use docker…"
                    sudo -v || { err "sudo authentication failed."; exit 1; }
                    SUDO="sudo"
                else
                    err  "docker requires sudo but no TTY is available to prompt for password."
                    info "hint: add your user to the docker group or enable passwordless sudo for docker."
                    exit 1
                fi
            fi
        else
            err "docker is not accessible and sudo is not installed."
            exit 1
        fi
    fi
fi

export SUDO
declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image() { _tmp_images+=("$1"); }

sudo_keepalive_start() {
    local max_minutes="${1:-60}"

    [[ "${SUDO:-}" != "sudo" ]] && return 0

    sudo -v || exit 1
    (
        local end=$((SECONDS + max_minutes*60))
        while (( SECONDS < end )); do
            sleep 60
            kill -0 "$PPID" 2>/dev/null || exit 0
            sudo -n -v 2>/dev/null || exit 0
        done
    ) & SUDO_KEEPALIVE_PID=$!
}
sudo_keepalive_stop() {
    if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
        unset SUDO_KEEPALIVE_PID
    fi
    if [[ "${SUDO:-}" == "sudo" ]]; then
        sudo -K 2>/dev/null || true
    fi
}
__compose() {
    if ${SUDO} docker compose version >/dev/null 2>&1; then
        ${SUDO} docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        ${SUDO} docker-compose "$@"
    else
        err "docker compose is not available."
        return 1
    fi
}
prune_build_caches() {
    ${SUDO} docker builder prune -af >/dev/null 2>&1 || true

    if ${SUDO} docker buildx ls >/dev/null 2>&1; then
        if ${SUDO} docker buildx ls --format '{{.Name}}' >/dev/null 2>&1; then
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                ${SUDO} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(${SUDO} docker buildx ls --format '{{.Name}}')
        else
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                ${SUDO} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(${SUDO} docker buildx ls | awk 'NR>1{print $1}')
        fi
    fi
}
preclean_patterns() {
    for name in exit_a exit_b haproxy support; do
        ${SUDO} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} ${SUDO} docker rm -f >/dev/null 2>&1 || true
    done
    local nets=()
    [[ -n "${ext_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$ext_network_container_subnet_cidr_ipv4" )
    [[ -n "${int_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$int_network_container_subnet_cidr_ipv4" )
    ${SUDO} docker network ls -q | while read -r nid; do
        subnets=$(${SUDO} docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
        for net in "${nets[@]}"; do
            if echo "$subnets" | grep -qw -- "$net"; then
                ${SUDO} docker network rm "$nid" >/dev/null 2>&1 || true
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
        ${SUDO} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} ${SUDO} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO} docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} ${SUDO} docker network rm >/dev/null 2>&1 || true
    ${SUDO} docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} ${SUDO} docker volume rm -f >/dev/null 2>&1 || true
    if [[ -z "$(${SUDO} docker ps -aq --filter ancestor=debian:trixie-slim 2>/dev/null)" ]]; then
        ${SUDO} docker rmi -f debian:trixie-slim >/dev/null 2>&1 || true
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
        ${SUDO:-} docker compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy deploy; do
        ${SUDO:-} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r:-} ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true

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
    cleanup_project "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"

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

    if ${SUDO} docker info >/dev/null 2>&1; then
        prune_build_caches

        if [[ "${STRICT_CLEANUP:-0}" == "1" ]]; then
            warn "Performing system-wide prune (--all --volumes)."
            ${SUDO} docker system prune -af --volumes >/dev/null 2>&1 || true
        fi
    fi

    sudo_keepalive_stop
    set -e
}
check_pkg() {
    local os=""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        info "Docker on macOS is ready."
        return 0
    fi

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os="$ID"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        case "$os" in
            debian)
                info "installing docker (Debian)…"
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
                info "installing docker (Arch/Manjaro)…"
                sudo pacman -Sy --needed --noconfirm docker docker-compose >/dev/null 2>&1
                ;;
            *)
                warn "unsupported distro '$os' – install docker manually."
                return 1
                ;;
        esac
    else
        info "docker is present."
    fi

    if command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service' ); then
        sudo systemctl enable --now docker 2>/dev/null || true
    fi
}
run_build_proxy() {
    local proj_dir="${tmp_folder}/${rnd_proj_name}"
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit_a,exit_b,haproxy,deploy}

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
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
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

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/exit_a/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_exit_a_ipv4
ARG tor_ctrl_pass
ARG tor_ctrl_hash

ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"
ENV tor_ctrl_hash="${tor_ctrl_hash}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN ASC=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1) && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${ASC}" | gpg --yes --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg && \
    echo "Types: deb deb-src\nComponents: main\nSuites: $(lsb_release -cs)\nURIs: https://deb.torproject.org/torproject.org\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/tor-archive-keyring.gpg" > /etc/apt/sources.list.d/tor.sources && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 700 /run/tor /var/lib/tor

RUN cat > /etc/tor/torrc <<EOL
Log notice file /dev/null
SocksPort ${int_network_container_exit_a_ipv4}:9095
ControlPort ${int_network_container_exit_a_ipv4}:9051
HashedControlPassword ${tor_ctrl_hash}
CookieAuthentication 0
DataDirectory /var/lib/tor
CircuitBuildTimeout 40
NewCircuitPeriod 30
EnforceDistinctSubnets 1
EOL

RUN cat > /usr/local/bin/healthcheck <<'EOL'
#!/bin/bash
set -e
host="${int_network_container_exit_a_ipv4}"
pass="${tor_ctrl_pass}"
nc -z "$host" 9095 >/dev/null 2>&1 || exit 1
nc -z "$host" 9051 >/dev/null 2>&1 || exit 1
resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
echo "$resp" | grep -q 'PROGRESS=100' || true
exit 0
EOL
RUN chmod +x /usr/local/bin/healthcheck

RUN apt-get purge -y lsb-release gnupg2 curl  && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER debian-tor
ENTRYPOINT ["tor","-f","/etc/tor/torrc"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/exit_b/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass
ARG tor_ctrl_hash

ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"
ENV tor_ctrl_hash="${tor_ctrl_hash}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN ASC=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1) && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${ASC}" | gpg --yes --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg && \
    echo "Types: deb deb-src\nComponents: main\nSuites: $(lsb_release -cs)\nURIs: https://deb.torproject.org/torproject.org\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/tor-archive-keyring.gpg" > /etc/apt/sources.list.d/tor.sources && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 700 /run/tor /var/lib/tor

RUN cat > /etc/tor/torrc <<EOL
Log notice file /dev/null
SocksPort ${int_network_container_exit_b_ipv4}:9095
ControlPort ${int_network_container_exit_b_ipv4}:9051
HashedControlPassword ${tor_ctrl_hash}
CookieAuthentication 0
DataDirectory /var/lib/tor
CircuitBuildTimeout 40
NewCircuitPeriod 30
EnforceDistinctSubnets 1
EOL

RUN cat > /usr/local/bin/healthcheck <<'EOL'
#!/bin/bash
set -e
host="${int_network_container_exit_b_ipv4}"
pass="${tor_ctrl_pass}"
nc -z "$host" 9095 >/dev/null 2>&1 || exit 1
nc -z "$host" 9051 >/dev/null 2>&1 || exit 1
resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
echo "$resp" | grep -q 'PROGRESS=100' || true
exit 0
EOL
RUN chmod +x /usr/local/bin/healthcheck

RUN apt-get purge -y lsb-release gnupg2 curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER debian-tor
ENTRYPOINT ["tor","-f","/etc/tor/torrc"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/haproxy/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ARG int_network_container_exit_a_ipv4
ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass

ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata haproxy curl netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN cat > /usr/local/bin/check-exit-control.sh <<'EOL'
#!/bin/bash
set -e
host="$3"
pass="${tor_ctrl_pass}"

if nc -z "$host" 9051 >/dev/null 2>&1; then
    resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
    echo "$resp" | grep -q 'PROGRESS=100' || true
    exit 0
fi

exit 1
EOL
RUN chmod +x /usr/local/bin/check-exit-control.sh

RUN cat <<EOL > /etc/haproxy/haproxy.cfg
global
    log stdout format raw local0
    maxconn 4096
    user haproxy
    group haproxy
    external-check
    insecure-fork-wanted

defaults
    log global
    mode tcp
    option  dontlognull
    retries 3
    timeout connect 5s
    timeout client  60s
    timeout server  60s

frontend socks_proxy
    bind ${int_network_container_haproxy_ipv4}:9095
    default_backend socks_pool

backend socks_pool
    balance roundrobin
    option external-check
    external-check path "/usr/bin:/bin:/usr/local/bin"
    external-check command "/usr/local/bin/check-exit-control.sh"
    server exit_a ${int_network_container_exit_a_ipv4}:9095 check inter 20s rise 1 fall 2
    server exit_b ${int_network_container_exit_b_ipv4}:9095 check inter 20s rise 1 fall 2
EOL

RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["haproxy","-f","/etc/haproxy/haproxy.cfg","-db"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/deploy/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ARG int_network_container_exit_a_ipv4
ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass

ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata bash sshpass openssh-client socat xz-utils coreutils libdigest-sha-perl gnupg2 && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN useradd -m user && chown -R user:user /home/user

RUN cat <<'SH' > /home/user/deploy
#!/bin/bash
set -Eeuo pipefail

tty_is_tty=0
if [[ -t 1 ]]; then
    tty_is_tty=1
    __orig_stty="$(stty -g 2>/dev/null || true)"
    stty -echoctl 2>/dev/null || true
fi

cleanup() {
    tput cnorm 2>/dev/null || true
    if [[ "${tty_is_tty}" -eq 1 ]]; then
        [[ -n "${__orig_stty:-}" ]] && stty "${__orig_stty}" 2>/dev/null || true
    fi
}
safe_fmt_date() {
    local _in="${1:-}"
    local _fmt="${2:-+%d.%m.%Y}"
    date -d "$_in" "$_fmt" 2>/dev/null || echo "$_in"
}
on_sigint() {
    if [[ -t 1 ]]; then
        printf '\e[2J\e[3J\e[H'
    fi
    echo "Interrupted by Ctrl+C. Exiting..."
    cleanup
    exit 130
}
on_sigterm() {
    if [[ -t 1 ]]; then
        printf '\e[2J\e[3J\e[H'
    fi
    echo "Received SIGTERM. Exiting..."
    cleanup
    exit 143
}

trap on_sigint INT
trap on_sigterm TERM
trap 'cleanup' EXIT

# Rotate Tor exit circuits for both exits (safe if env vars are missing)
tor_newnym() {
    local pass="${tor_ctrl_pass:-}"
    local exit_a="${int_network_container_exit_a_ipv4:-}"
    local exit_b="${int_network_container_exit_b_ipv4:-}"

    if [[ -z "$pass" || -z "$exit_a" || -z "$exit_b" ]]; then
        echo "Tor control parameters are not set; skipping circuit rotation."
        return 0
    fi

    local ok=0
    local resp_a
    resp_a="$(printf 'AUTHENTICATE "%s"\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$pass" | socat - TCP4:"$exit_b":9051,connect-timeout=3 2>/dev/null || true)"
    echo "$resp_a" | grep -q '250 OK' && ok=$((ok+1))

    local resp_b
    resp_b="$(printf 'AUTHENTICATE "%s"\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$pass" | socat - TCP4:"$exit_a":9051,connect-timeout=3 2>/dev/null || true)"
    echo "$resp_b" | grep -q '250 OK' && ok=$((ok+1))

    if [[ "$ok" -eq 2 ]]; then
        echo "Tor exit circuit rotated."
    else
        echo "Tor NEWNYM signal sent."
    fi
}
clear_screen() {
    clear
    printf '\e[3J'
}
_rand32() {
    local n
    n="$(od -An -N4 -tu4 /dev/urandom)"
    printf '%s' "${n//[[:space:]]/}"
}
_rand_range() {
    local min="${1:-}" max="${2:-}" range lim r
    [[ -n "$min" && -n "$max" && "$min" =~ ^[0-9]+$ && "$max" =~ ^[0-9]+$ && "$min" -lt "$max" ]] || { printf '%s\n' "invalid range values" >&2; return 1; }
    range=$((max - min + 1))
    lim=$(( (4294967296 / range) * range - 1 ))
    while :; do
        r="$(_rand32)"
        (( r <= lim )) && break
    done
    printf '%s\n' $(( r % range + min ))
}
_bad_bot_patterns() {
    local s="${1-}"
    local n=${#s} i=0
    (( n == 0 )) && return 1
    for ((i=0; i+1<n; i++)); do [[ "${s:i:1}" == "${s:i+1:1}" ]] && return 0; done
    [[ "$s" == *01234* || "$s" == *12345* || "$s" == *23456* || "$s" == *34567* || "$s" == *45678* || "$s" == *56789* ]] && return 0
    if (( n >= 5 )); then
        for ((i=0; i+4<n; i++)); do [[ "${s:i:1}" == "${s:i+2:1}" && "${s:i+2:1}" == "${s:i+4:1}" ]] && return 0; done
    fi
    if (( n == 5 )); then
        [[ "${s:0:1}" == "${s:4:1}" && "${s:1:1}" == "${s:3:1}" ]] && return 0
        [[ "${s:0:1}" == "${s:3:1}" && "${s:1:1}" == "${s:4:1}" ]] && return 0
    fi
    if (( n >= 4 )); then
        for ((i=0; i+3<n; i++)); do [[ "${s:i:1}" == "${s:i+2:1}" && "${s:i+1:1}" == "${s:i+3:1}" ]] && return 0; done
    fi
    return 1
}
generate_ssh_keys() {
    local dir old_umask public_ed25519_key private_ed25519_key
    dir="$(mktemp -d)"
    old_umask="$(umask)"
    umask 077
    trap 'umask "$old_umask"; rm -rf "$dir"; trap - RETURN ERR' RETURN ERR
    command -v ssh-keygen >/dev/null 2>&1 || { printf 'ssh-keygen not found\n' >&2; return 1; }
    ssh-keygen -q -t ed25519 -a 100 -N "" -f "$dir/id_ed25519" >/dev/null 2>&1 || return 1
    public_ed25519_key="$(cut -d' ' -f1-2 "$dir/id_ed25519.pub")"
    private_ed25519_key="$(xz -9e -c "$dir/id_ed25519" | base64 -w 0)"
    printf '%s %s\n' "$private_ed25519_key" "$public_ed25519_key"
}
generate_username() {
    local len=18 out='' cs='a-zA-Z0-9' ch
    declare -A used=()
    local first
    while :; do first=$(LC_ALL=C tr -dc 'a-zA-Z' </dev/urandom | head -c 1 || true); [[ -n $first ]] && break; done
    out+="$first"; used["$first"]=1
    while [ ${#out} -lt $((len - 1)) ]; do
        ch=$(LC_ALL=C tr -dc "$cs" </dev/urandom | head -c 1 || true)
        [[ -z $ch || ${used[$ch]+x} ]] && continue
        used["$ch"]=1; out+="$ch"
    done
    while :; do
        ch=$(LC_ALL=C tr -dc 'a-zA-Z' </dev/urandom | head -c 1 || true)
        [[ -n $ch && ! ${used[$ch]+x} ]] && { out+="$ch"; break; }
    done
    printf '%s\n' "$out"
}
generate_user_group() {
    local len=8 out='' cs='a-z' ch
    declare -A used=()
    local first
    while :; do first=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 1 || true); [[ -n $first ]] && break; done
    out+="$first"; used["$first"]=1
    while [ ${#out} -lt $((len - 1)) ]; do
        ch=$(LC_ALL=C tr -dc "$cs" </dev/urandom | head -c 1 || true)
        [[ -z $ch || ${used[$ch]+x} ]] && continue
        used["$ch"]=1; out+="$ch"
    done
    while :; do
        ch=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 1 || true)
        [[ -n $ch && ! ${used[$ch]+x} ]] && { out+="$ch"; break; }
    done
    printf '%s\n' "$out"
}
generate_port() {
    local min="${1:-}" max="${2:-}" port prev diff i d1 d2 ok
    [[ -n "$min" && -n "$max" && "$min" =~ ^[0-9]+$ && "$max" =~ ^[0-9]+$ && "$min" -lt "$max" ]] || { printf '%s\n' "invalid range values" >&2; return 1; }
    while :; do
        port="$(_rand_range "$min" "$max")"
        for prev in "${generated_ports[@]}"; do [[ "$prev" == "$port" ]] && continue 2; done
        _bad_bot_patterns "$port" && continue
        ok=1
        for (( i=0; i<${#port}-1; i++ )); do
            d1=${port:$i:1}; d2=${port:$i+1:1}
            diff=$(( d1>d2 ? d1-d2 : d2-d1 ))
            (( diff < 2 )) && { ok=0; break; }
        done
        (( ok )) || continue
        generated_ports+=("$port")
        printf '%s\n' "$port"
        break
    done
}
generate_password() {
    local specials='<>*+!?_=#@%&'
    local need_spec=7 spec_cnt=0
    local first last pass len=45 total ch i mid
    total=$((len + 2))
    declare -A used=()
    declare -A used_spec=()
    while :; do first=$(LC_ALL=C tr -dc 'A-Za-z' </dev/urandom | head -c 1 || true); [[ -n $first ]] && break; done
    pass="$first"; used["$first"]=1
    while [[ ${#pass} -lt $total || $spec_cnt -lt $need_spec ]]; do
        ch=$(LC_ALL=C tr -dc 'A-Za-z0-9<>*+!?_=#@%&' </dev/urandom | head -c 1 || true)
        [[ -z $ch || ${used[$ch]+x} ]] && continue
        if [[ "$specials" == *"$ch"* && -z ${used_spec[$ch]+x} ]]; then used_spec["$ch"]=1; ((spec_cnt++)); fi
        pass+="$ch"; used["$ch"]=1
        if [[ ${#pass} -eq $total && $spec_cnt -lt $need_spec ]]; then
            pass="$first"; spec_cnt=0
            unset used used_spec
            declare -A used=() used_spec=()
            used["$first"]=1
        fi
    done
    while :; do last=$(LC_ALL=C tr -dc 'A-Za-z' </dev/urandom | head -c 1 || true); [[ -n $last && -z ${used[$last]+x} ]] && break; done
    pass+="$last"
    _permute_middle() {
        local s n i j tmp
        local -a a=()
        s="${1-}"
        n=${#s}
        if (( n == 0 )); then printf ''; return; fi
        i=0
        while (( i < n )); do a[i]="${s:i:1}"; i=$((i+1)); done
        i=$((n-1))
        while (( i > 0 )); do
            j=$(_rand_range 0 "$i")
            tmp="${a[i]}"; a[i]="${a[j]}"; a[j]="$tmp"
            i=$((i-1))
        done
        printf '%s' "${a[@]}"
    }
    for i in {1..5}; do
        mid=$(_permute_middle "${pass:1:-1}")
        pass="${first}${mid}${last}"
    done
    printf '%s\n' "$pass"
}
get_tokens() {
    set -euo pipefail
    local profile="${1:-}"; [ -n "$profile" ] || { echo "usage: get_tokens <support|deploy>" >&2; return 2; }
    local payload t
    case "$profile" in
        support)
          payload="ssh_raw=${private_ed25519_key}\\nssh_user_password='${host_user_password}'\\nssh_user=${host_user}\\nssh_port=${host_ssh_port}\\nsrv_ip=${vps_address}"
          ;;
        deploy)
          payload="ssh_raw=${private_deploy_ed25519_key}\\nssh_user=deploy\\nssh_port=${host_ssh_port}\\nsrv_ip=${vps_address}"
          ;;
        *) echo "unknown profile: $profile" >&2; return 2 ;;
    esac

    local p="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 45 || true)"
    local b64="$(printf '%s' "$payload" | xz -9e | gpg --batch --yes --no-tty --quiet --pinentry-mode loopback --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-mode 3 --s2k-count 65011712 --compress-algo none --passphrase "$p" --output - 2>/dev/null | base64 -w 0)"
    local h="jA0ECQMK"
    if [[ "${b64:0:${#h}}" == "$h" ]]; then
        t="${b64:${#h}}"
    else
        echo "bad header" >&2
        return 3
    fi
    printf '%s%s\n' "$p" "$t"
}
print_tokens() {
    deploy_key="$(get_tokens deploy)"
    support_key="$(get_tokens support)"

cat <<CONF
------------------------------------------------
Copy [Stage 2] Tokens to Crypto Notes/KeePassXC
------------------------------------------------
[Stage 2] Deploy Token:
${deploy_key}

[Stage 2] Support Token:
${support_key}
------------------------------------------------
CONF
}
configure_server_installer() {
cat <<'EOS' > /tmp/install.sh
#!/bin/bash 

indent() {
    local arg="${1:-}"
    local mode
    local num
    if [[ "$arg" =~ ^([+-])([0-9]+)$ ]]; then
        mode="${BASH_REMATCH[1]}"
        num="${BASH_REMATCH[2]}"
    else
        mode="$arg"
        num="${2:-0}"
    fi
    case "$mode" in
        +) sed "s/^/$(printf '%*s' "$num")/";;
        -) sed -E "s/^ {0,$num}//";;
        0) awk '{ $1=$1; print }';;
        *) return 1;;
    esac
}
_codename() {
    local codename=""
    declare -A codename_count
    tmp_names=()
    add_to_temp() { [ -n "$1" ] && tmp_names+=("$1"); }
    [ -f /etc/os-release ] && add_to_temp "$(grep -oP '(?<=VERSION_CODENAME=)\w+' /etc/os-release 2>/dev/null)"
    [ -f /boot/grub/grub.cfg ] && add_to_temp "$(grep -oP '(?<=menuentry '\''Debian GNU/Linux )[^ ]+' /boot/grub/grub.cfg | head -n 1 2>/dev/null)"
    [ -f /etc/apt/sources.list ] && add_to_temp "$(grep -m1 -Po '(?<=/debian/)\w+' /etc/apt/sources.list 2>/dev/null)"
    [ -f /etc/default/grub ] && add_to_temp "$(grep -oP '(?<=GRUB_DISTRIBUTOR=")[^"]+' /etc/default/grub 2>/dev/null)"
    add_to_temp "$(grep -oP 'debian[^ ]+' /proc/cmdline 2>/dev/null)"
    [ -f /boot/config-$(uname -r) ] && add_to_temp "$(grep -oP 'debian[^-]*' /boot/config-$(uname -r) 2>/dev/null)"
    [ -f /etc/motd ] && add_to_temp "$(grep -oP '(Debian GNU/Linux \K[^ ]+)' /etc/motd 2>/dev/null)"
    ls /var/lib/apt/lists/*_InRelease >/dev/null 2>&1 && add_to_temp "$(grep -oP '(?<=dists/)[^/ ]+' /var/lib/apt/lists/*_InRelease | head -n 1 2>/dev/null)"
    for name in "${tmp_names[@]}"; do [ -n "$name" ] && codename_count["$name"]=$((codename_count["$name"]+1)); done
    for name in "${!codename_count[@]}"; do [ -z "$codename" ] || [ "${codename_count[$name]}" -gt "${codename_count[$codename]}" ] && codename=$name; done
    [ -z "$codename" ] && { echo "Failed to detect Debian codename";return 1; }
    echo "$codename"
}
_is_ipv6_modular() {
    local fn krel
    if fn="$(modinfo -F filename ipv6 2>/dev/null)"; then
        [ -n "$fn" ] && [ "$fn" != "(builtin)" ] && return 0
        return 1
    fi
    krel="$(uname -r)"
    grep -qsE '/ipv6\.ko(\.(gz|xz|zst))?$' "/lib/modules/${krel}/modules.dep" && return 0
    grep -qsE '/ipv6\.ko(\.(gz|xz|zst))?$' "/lib/modules/${krel}/modules.builtin" && return 1
    return 1
}
configure_repo() {
    local codename="$(_codename)"
    install -d -m 0755 -o root -g root /etc/apt/keyrings /etc/apt/sources.list.d/
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources /etc/apt/trusted.gpg.d/debian-archive-*.asc
    [ -f /etc/apt/trusted.gpg ] && rm -f /etc/apt/trusted.gpg || true
    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/sources.list.d/debian.sources
    Types: deb deb-src
    URIs: https://deb.debian.org/debian
    Suites: ${codename} ${codename}-updates
    Components: main
    Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
    
    Types: deb deb-src
    URIs: https://security.debian.org/debian-security
    Suites: ${codename}-security
    Components: main
    Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
CONF
}
install_base_packages() {
    export DEBIAN_FRONTEND=noninteractive
    rm -rf /var/lib/apt/lists/*
    apt-get update >/dev/null 2>&1 && apt-get -o Dpkg::Options::="--force-confold" upgrade -y --allow-downgrades --allow-remove-essential --allow-change-held-packages >/dev/null 2>&1
    local packages=("lsb-release" "apt-transport-https" "ca-certificates" "gnupg2" "curl")
    for pkg in "${packages[@]}"; do 
        apt-get install --no-install-recommends -y $pkg >/dev/null 2>&1
    done
}
install_iptables() {
    apt-get update >/dev/null 2>&1
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get -y install iptables-persistent >/dev/null 2>&1
}
install_docker() {
    install -d -m 0755 -o root -g root /etc/apt/keyrings
    local arch="$(dpkg --print-architecture)"
    local codename="$(lsb_release -cs 2>/dev/null)"
    curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/keyrings/docker.gpg
    printf "Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.gpg\n" "$codename" "$arch" > /etc/apt/sources.list.d/docker.sources
    printf "Package: *\nPin: origin download.docker.com\nPin-Priority: 900\n" > /etc/apt/preferences.d/docker
    apt-get update >/dev/null 2>&1
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1
}
install_gvisor() {
    install -d -m 0755 -o root -g root /etc/apt/keyrings
    local suite="${1:-release}"
    local arch="$(dpkg --print-architecture)"
    curl -fsSL --proto '=https' --tlsv1.3 https://gvisor.dev/archive.key | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/keyrings/gvisor.gpg
    printf "Types: deb\nURIs: https://storage.googleapis.com/gvisor/releases\nSuites: %s\nComponents: main\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/gvisor.gpg\n" "$suite" "$arch" > /etc/apt/sources.list.d/gvisor.sources
    printf "Package: runsc\nPin: origin storage.googleapis.com\nPin-Priority: 900\n" > /etc/apt/preferences.d/gvisor
    apt-get update >/dev/null 2>&1
    apt-get install -y runsc >/dev/null 2>&1
    configure_docker_daemon
    systemctl daemon-reload
    systemctl stop docker.{socket,service} >/dev/null 2>&1
    systemctl start docker.{socket,service} >/dev/null 2>&1
}
configure_timezone() {
    timedatectl set-timezone UTC
}
configure_locales() {
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends locales >/dev/null 2>&1

    if ! grep -q '^en_US\.UTF-8 UTF-8' /etc/locale.gen 2>/dev/null; then
        if grep -q '^# *en_US\.UTF-8 UTF-8' /etc/locale.gen 2>/dev/null; then
            sed -i 's/^# *\(en_US\.UTF-8 UTF-8\)/\1/' /etc/locale.gen >/dev/null 2>&1
        else
            echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
        fi
    fi

    locale-gen >/dev/null 2>&1 || true

    install -d -m 0755 -o root -g root /etc/default
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/default/locale
    LANG=en_US.UTF-8
    LANGUAGE=en_US:en
CONF

    sed -i '/LC_ALL=/d;/LC_CTYPE=/d' /root/.bashrc 2>/dev/null || true
    for f in /home/*/.bashrc /home/*/.profile; do
        [ -f "$f" ] || continue
        sed -i '/LC_ALL=/d;/LC_CTYPE=/d' "$f" >/dev/null 2>&1 || true
    done
}
configure_path() {
    set -euo pipefail
    local path_system="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    if [ -f /etc/environment ]; then
        if grep -q '^PATH=' /etc/environment 2>/dev/null; then
            sed -i 's#^PATH=.*#PATH='"$path_system"'#' /etc/environment >/dev/null 2>&1
        else
            printf 'PATH=%s\n' "$path_system" >> /etc/environment
        fi
    else
        printf 'PATH=%s\n' "$path_system" > /etc/environment
    fi

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/profile.d/00-path-sbin.sh
    # Ensure sbin directories are present in PATH for interactive shells
    case ":$PATH:" in
        *:/usr/sbin:*)
            ;;
        *)
            PATH="$PATH:/usr/sbin"
            ;;
    esac

    case ":$PATH:" in
        *:/sbin:*)
            ;;
        *)
            PATH="$PATH:/sbin"
            ;;
    esac

    export PATH
CONF

    if [ -x /usr/sbin/visudo ]; then
        install -d -m 0755 -o root -g root /etc/sudoers.d >/dev/null 2>&1 || true
        cat <<'CONF' | indent 0 | install -D -m 0440 -o root -g root /dev/stdin /etc/sudoers.d/00-default-path
        Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CONF
        visudo -cf /etc/sudoers >/dev/null 2>&1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        install -d -m 0755 -o root -g root /etc/systemd/system.conf.d >/dev/null 2>&1 || true
        cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system.conf.d/path.conf
        [Manager]
        DefaultEnvironment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CONF
        systemctl daemon-reexec >/dev/null 2>&1 || true
    fi

    if [ -f /etc/crontab ]; then
        if grep -q '^PATH=' /etc/crontab 2>/dev/null; then
            sed -i 's#^PATH=.*#PATH='"$path_system"'#' /etc/crontab >/dev/null 2>&1
        else
            sed -i '1i PATH='"$path_system" /etc/crontab >/dev/null 2>&1
        fi
    fi

    for f in /etc/cron.d/*; do
        [ -f "$f" ] || continue
        if grep -q '^PATH=' "$f" 2>/dev/null; then
            sed -i 's#^PATH=.*#PATH='"$path_system"'#' "$f" >/dev/null 2>&1
        fi
    done
}
setup_user() {
    groupadd -f "$host_user_group"
    id -u "$host_user" >/dev/null 2>&1 || useradd -m -d "/home/${host_user}" -s /bin/bash "$host_user"
    echo "${host_user}:${host_user_password}" | chpasswd
    unset host_user_password
    usermod -aG sudo "$host_user"
    usermod -aG "$host_user_group" "$host_user"
    install -d -m 700 -o "$host_user" -g "$host_user" "/home/${host_user}/.ssh"
    printf '%s\n' "$host_user_pubkey_ed25519" | install -m 600 -o "$host_user" -g "$host_user" /dev/stdin "/home/${host_user}/.ssh/authorized_keys"

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/profile.d/nohist-${host_user}.sh
    [ "\$USER" = "${host_user}" ] || return
    case \$- in *i*)
        export HISTFILE=/dev/null
        export HISTSIZE=0
        export HISTFILESIZE=0
        export HISTFILE HISTSIZE HISTFILESIZE
        set +o history
        PROMPT_COMMAND=''
    ;; esac
CONF

    su - "${host_user}" -c 'rm -f ~/.bash_history; : > ~/.bash_history'
    chown root:root "/home/${host_user}/.bash_history"
    chmod 000 "/home/${host_user}/.bash_history"
    chattr +i "/home/${host_user}/.bash_history" 2>/dev/null || true
    truncate -s 0 /etc/motd /etc/issue /etc/issue.net
    mv /etc/update-motd.d/10-uname /etc/update-motd.d/10-uname.disabled
}
setup_deploy_user() {
    install -d -m 0755 -o root -g root /var/empty
    groupadd -f deploy
    id -u deploy >/dev/null 2>&1 || useradd -M -d /var/empty -s /bin/sh -g deploy deploy
    usermod -d /var/empty -s /bin/sh -g deploy deploy
    passwd -l deploy >/dev/null 2>&1 || true
    install -d -m 0755 -o root -g root /var/ssh
    install -d -m 0700 -o deploy -g deploy /var/ssh/deploy
    printf '%s\n' "$host_deploy_pubkey_ed25519" | install -m 0600 -o deploy -g deploy /dev/stdin /var/ssh/deploy/authorized_keys
    install -d -m 0755 -o root -g root /var/run/sshd >/dev/null 2>&1 || true

    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/ssh-guard
    #!/bin/sh
    set -Eeuo pipefail
    umask 077
    PATH=/usr/sbin:/usr/bin:/bin
    
    cmd=$(printf "%s" "${SSH_ORIGINAL_COMMAND:-}" | tr -d '\r')
    [ -n "$cmd" ] || exit 126
    
    ensure_tmpdir() {
        [ -d /tmp/deploy ] || mkdir -p /tmp/deploy
        chmod 1777 /tmp/deploy 2>/dev/null || true
    }
    
    gen_name() {
        rid=""
        if command -v uuidgen >/dev/null 2>&1; then
            rid="$(uuidgen)"
        elif [ -r /proc/sys/kernel/random/uuid ]; then
            rid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null)"
        else
            rid="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
        fi
        rid="${rid%%-*}"
        rid="$(printf "%s" "$rid" | tr 'A-F' 'a-f' | cut -c1-8)"
        printf "%s.tar.xz" "$rid"
    }
    
    sha256_of() {
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$1" | awk '{print $1}'
        else
            shasum -a 256 "$1" | awk '{print $1}'
        fi
    }
    
    do_upload() {
        ensure_tmpdir
        name="$(gen_name)"
        file="/tmp/deploy/$name"
        /bin/cat > "$file"
        sha="$(sha256_of "$file")"
        printf "%s %s\n" "$name" "$sha"
    }
    
    case "$cmd" in
        upload)
            do_upload
            exit 0
            ;;
        upload-deploy)
            out="$(do_upload)" || exit 1
            /usr/bin/sudo -n /usr/bin/systemctl start --no-block deploy.service || exit 1
            printf "%s\n" "$out"
            exit 0
            ;;
        'sudo systemctl start deploy.service'|\
        'sudo systemctl start restore.service'|\
        'sudo systemctl start wipe.service')
            exec /bin/sh -c "$cmd"
            ;;
        *)
            printf 'denied\n' >&2
            exit 126
            ;;
    esac
CONF

    cat <<CONF | indent 0 | install -D -m 0440 -o root -g root /dev/stdin /etc/sudoers.d/deploy
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start deploy.service
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block deploy.service
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start restore.service
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block restore.service
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start wipe.service
    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block wipe.service
CONF
    visudo -cf /etc/sudoers.d/deploy

    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/tmpfiles.d/deploy-tmp.conf
    d /tmp/deploy 1777 root root -
    z /tmp/deploy 1777 root root -
CONF
    systemd-tmpfiles --create /etc/tmpfiles.d/deploy-tmp.conf
}
configure_root_access() {
    passwd -l root
}
configure_faillock_debian() {
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/security/faillock.conf
    deny=3
    fail_interval=60
    unlock_time=120
CONF

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /usr/share/pam-configs/faillockpre
    Name: Faillock Preauth
    Default: no
    Priority: 384
    Auth-Type: Primary
    Auth:
        required pam_faillock.so preauth
CONF

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /usr/share/pam-configs/faillockmain
    Name: Faillock Main
    Default: no
    Priority: 64
    Auth-Type: Primary
    Auth:
        [default=die] pam_faillock.so authfail
CONF

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /usr/share/pam-configs/faillockpost
    Name: Faillock Authsucc
    Default: no
    Priority: 128
    Auth-Type: Additional
    Auth:
        sufficient pam_faillock.so authsucc
CONF

    pam-auth-update --enable faillockpre --enable faillockmain --enable faillockpost --force
}
configure_security_update() {
    apt-get update >/dev/null 2>&1; apt-get install --no-install-recommends -y unattended-upgrades apt-listchanges >/dev/null 2>&1
    install -d -m 0755 -o root -g root /etc/apt/apt.conf.d
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/apt.conf.d/50unattended-upgrades
    Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    };
    Unattended-Upgrade::Remove-Unused-Dependencies "false";
    Dpkg::Options {
        "--force-confdef";
        "--force-confold";
    };
CONF
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/apt.conf.d/20auto-upgrades
    APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Download-Upgradeable-Packages "1";
    APT::Periodic::AutocleanInterval "7";
    APT::Periodic::Unattended-Upgrade "1";
CONF
}
configure_iptables() {
    local host_net_ipv4_public_if_name="$(ip -4 route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $5}')"
    [ -n "${host_net_ipv4_public_if_name:-}" ] || host_net_ipv4_public_if_name="$(ip -o link | awk -F': ' '$2 ~ /^(eth|ens|enp)/{print $2; exit}')"
    local host_net_ipv4_public_if_addr="$(LC_ALL=C ip -4 route get 255.255.255.255 2>/dev/null | grep -Po 'src\s+\K([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"

    install -d -m 0755 -o root -g root /etc/iptables/
    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/iptables/rules.v4
    *raw
    :PREROUTING ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    COMMIT
    
    *mangle
    :PREROUTING ACCEPT [0:0]
    :INPUT ACCEPT [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :POSTROUTING ACCEPT [0:0]
    
    -A FORWARD -o ${host_net_ipv4_public_if_name} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    COMMIT
    
    *filter
    :INPUT DROP [0:0]
    :FORWARD DROP [0:0]
    :OUTPUT DROP [0:0]
    :DOCKER-USER [0:0]
    
    -A INPUT -i lo -j ACCEPT
    -A OUTPUT -o lo -j ACCEPT
    -A INPUT -m conntrack --ctstate INVALID -j DROP
    -A FORWARD -m conntrack --ctstate INVALID -j DROP
    -A OUTPUT -m conntrack --ctstate INVALID -j DROP
    -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    -A INPUT -i ${host_net_ipv4_public_if_name} -m addrtype --src-type BROADCAST,MULTICAST -j DROP
    -A INPUT -i ${host_net_ipv4_public_if_name} -m addrtype --dst-type BROADCAST,MULTICAST -j DROP
    -A INPUT -i ${host_net_ipv4_public_if_name} -s 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,0.0.0.0/8,192.0.2.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24 -j DROP
    -A INPUT -i ${host_net_ipv4_public_if_name} -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,0.0.0.0/8,224.0.0.0/4,240.0.0.0/4,255.255.255.255/32 -j DROP
    -A INPUT -i ${host_net_ipv4_public_if_name} -s ${host_net_ipv4_public_if_addr}/32 -j DROP
    -A INPUT -f -j DROP
    -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    -A INPUT -p icmp --icmp-type echo-request -j DROP
    -A INPUT -p icmp --icmp-type redirect -j DROP
    -A INPUT -p icmp --icmp-type source-quench -j DROP
    -A INPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT
    -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    -A INPUT -i ${host_net_ipv4_public_if_name} -p tcp --dport ${host_ssh_port} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name ssh4 --hashlimit-mode srcip --hashlimit-above 30/min --hashlimit-burst 30 -j DROP
    -A INPUT -i ${host_net_ipv4_public_if_name} -p tcp --dport ${host_ssh_port} -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp -d 1.1.1.1 --dport 853 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp -d 1.0.0.1 --dport 853 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp -d 94.140.14.140 --dport 853 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp -d 94.140.14.141 --dport 853 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 4123 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp --dport 4460 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp --dport 53 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 784 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p tcp --dport 853 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -d 169.254.169.254 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o ${host_net_ipv4_public_if_name} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
    -A OUTPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT
    -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    -A DOCKER-USER -i ${host_net_ipv4_public_if_name} -m conntrack --ctstate INVALID -j DROP
    -A DOCKER-USER -i ${host_net_ipv4_public_if_name} -m addrtype --src-type BROADCAST,MULTICAST -j DROP
    -A DOCKER-USER -i ${host_net_ipv4_public_if_name} -s 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,0.0.0.0/8 -j DROP
    -A DOCKER-USER -o ${host_net_ipv4_public_if_name} -p udp --dport 784 -j DROP
    -A DOCKER-USER -o ${host_net_ipv4_public_if_name} -p udp --dport 853 -j DROP
    -A DOCKER-USER -o ${host_net_ipv4_public_if_name} -p tcp --dport 853 -j DROP
    -A DOCKER-USER -o ${host_net_ipv4_public_if_name} -p udp --dport 443 -j DROP
    -A DOCKER-USER -i docker+ -o ${host_net_ipv4_public_if_name} -d 169.254.169.254/32 -j REJECT --reject-with icmp-port-unreachable
    -A DOCKER-USER -i br+ -o ${host_net_ipv4_public_if_name} -d 169.254.169.254/32 -j REJECT --reject-with icmp-port-unreachable
    -A DOCKER-USER -i docker+ -o ${host_net_ipv4_public_if_name} -p udp -m conntrack --ctstate NEW -j RETURN
    -A DOCKER-USER -i br+ -o ${host_net_ipv4_public_if_name} -p udp -m conntrack --ctstate NEW -j RETURN
    -A DOCKER-USER -i docker+ -o ${host_net_ipv4_public_if_name} -p tcp -m conntrack --ctstate NEW -j RETURN
    -A DOCKER-USER -i br+ -o ${host_net_ipv4_public_if_name} -p tcp -m conntrack --ctstate NEW -j RETURN
    -A DOCKER-USER -j RETURN
    COMMIT
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/iptables/rules.v6
    *filter
    :INPUT DROP [0:0]
    :FORWARD DROP [0:0]
    :OUTPUT DROP [0:0]
    COMMIT
CONF

    iptables-restore < /etc/iptables/rules.v4
    ip6tables-restore < /etc/iptables/rules.v6
}
configure_apparmor() {
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends apparmor apparmor-utils >/dev/null 2>&1 || true
    
    install -d -m 0755 -o root -g root /etc/apparmor.d/
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apparmor.d/docker-matrix-postgres
    #include <tunables/global>
    profile docker-matrix-postgres flags=(attach_disconnected, complain, mediate_deleted) {
      network,
      capability,
      file,
      signal,
    
      /var/lib/postgresql/** rwk,
      /var/run/postgresql/** rwk,
    
      /etc/hosts r,
      /etc/hostname r,
      /etc/resolv.conf r,
      /etc/localtime r,
    
      /usr/** r,
      /lib/** r,
      /lib64/** r,
      /bin/** r,
      /sbin/** r,
    
      /proc/** r,
      /sys/** r,
    
      /dev/** rw,
    }
CONF
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apparmor.d/docker-matrix-redis
    #include <tunables/global>
    profile docker-matrix-redis flags=(attach_disconnected,mediate_deleted) {
      signal,
      signal (receive) set=(hup,term,kill,stop,cont,usr1,usr2),
      signal (send) set=(hup,term,kill,stop,cont,usr1,usr2) peer=unconfined,
    
      network,
      capability,
      file,
    
      /data/** rwk,
      /tmp/** rwk,
    
      /etc/hosts r,
      /etc/hostname r,
      /etc/resolv.conf r,
      /etc/localtime r,
    
      /usr/** r,
      /lib/** r,
      /lib64/** r,
      /bin/** r,
      /sbin/** r,
    
      /proc/** r,
      /sys/** r,
      /dev/** rw,
    }
CONF
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apparmor.d/docker-matrix-synapse
    #include <tunables/global>
    profile docker-matrix-synapse flags=(attach_disconnected,mediate_deleted) {
      signal,
      signal (receive) set=(hup,term,kill,stop,cont,usr1,usr2),
      signal (send) set=(hup,term,kill,stop,cont,usr1,usr2) peer=unconfined,
    
      network,
      capability,
      file,
    
      /data/** rwk,
    
      /etc/hosts r,
      /etc/hostname r,
      /etc/resolv.conf r,
      /etc/localtime r,
    
      /usr/** r,
      /lib/** r,
      /lib64/** r,
      /bin/** r,
      /sbin/** r,
    
      /proc/** r,
      /sys/** r,
      /dev/** rw,
    }
CONF
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/apparmor.d/docker-matrix-tunnel
    #include <tunables/global>
    profile docker-matrix-tunnel flags=(attach_disconnected,mediate_deleted) {
      signal,
      signal (receive) set=(hup,term,kill,stop,cont,usr1,usr2),
      signal (send) set=(hup,term,kill,stop,cont,usr1,usr2) peer=unconfined,
    
      network,
      capability,
      file,
    
      /ssh/** r,
      /tmp/** rwk,
      /dev/shm/** rwk,
    
      /usr/bin/ssh ixr,
      /usr/bin/curl ixr,
      /bin/sh ixr,
      /bin/bash ixr,
      /usr/** r,
      /lib/** r,
      /lib64/** r,
      /bin/** r,
      /sbin/** r,
    
      /etc/hosts r,
      /etc/hostname r,
      /etc/resolv.conf r,
      /etc/localtime r,
      /etc/ssl/** r,
    
      /proc/** r,
      /sys/** r,
      /dev/** rw,
    }
CONF
    systemctl enable --now apparmor || true
    apparmor_parser -r /etc/apparmor.d/docker-matrix-postgres || true
    apparmor_parser -r /etc/apparmor.d/docker-matrix-redis || true
    apparmor_parser -r /etc/apparmor.d/docker-matrix-synapse || true
    apparmor_parser -r /etc/apparmor.d/docker-matrix-tunnel || true
}
configure_seccomp() {
    install -d -m 0755 -o root -g root /etc/docker/
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/docker/seccomp-matrix.json
    {
      "defaultAction": "SCMP_ACT_ALLOW",
      "architectures": [
        "SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_AARCH64","SCMP_ARCH_ARM"
      ],
      "syscalls": [
        {
          "names": [
            "bpf","perf_event_open","ptrace",
            "process_vm_readv","process_vm_writev",
            "fanotify_init","fanotify_mark",
            "kexec_load","kexec_file_load","reboot",
            "keyctl","add_key","request_key",
            "mount","umount2","pivot_root",
            "move_mount","open_tree","fsopen","fsconfig","fsmount","fspick",
            "setns","unshare",
            "syslog",
            "iopl","ioperm",
            "init_module","finit_module","delete_module"
          ],
          "action": "SCMP_ACT_ERRNO"
        },
        {
          "names": [
            "userfaultfd","open_by_handle_at","name_to_handle_at","kcmp",
            "acct","swapoff","swapon","uselib","_sysctl"
          ],
          "action": "SCMP_ACT_ERRNO"
        },
        {
          "names": ["io_uring_setup","io_uring_register","io_uring_enter"],
          "action": "SCMP_ACT_ERRNO"
        },
        {
          "names": ["pidfd_open","pidfd_getfd","pidfd_send_signal"],
          "action": "SCMP_ACT_ERRNO"
        },
        {
          "names": ["chroot"],
          "action": "SCMP_ACT_ERRNO"
        },
        {
          "names": ["socket"],
          "action": "SCMP_ACT_ERRNO",
          "args": [{ "index": 0, "value": 16, "op": "SCMP_CMP_EQ" }]
        },
        {
          "names": ["socket"],
          "action": "SCMP_ACT_ERRNO",
          "args": [{ "index": 0, "value": 17, "op": "SCMP_CMP_EQ" }]
        },
        {
          "names": ["ioctl"],
          "action": "SCMP_ACT_ERRNO",
          "args": [{ "index": 1, "value": 21522, "op": "SCMP_CMP_EQ" }]
        }
      ]
    }
CONF
}
configure_docker_daemon() {
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/docker/daemon.json
    {
      "iptables": true,
      "log-driver": "none",
      "ipv6": false,
      "log-level": "error",
      "userland-proxy": false,
      "runtimes": {
        "runsc": {
          "path": "/usr/bin/runsc"
        }
      }
    }
CONF
}
configure_sysctl() {
    local mem_kib
    mem_kib=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local gib=$(( (mem_kib + 1048575) / 1048576 )); [ "$gib" -lt 1 ] && gib=1
    local nfct=$(( gib * 32768 ))
    [ "$nfct" -lt 65536 ] && nfct=65536
    [ "$nfct" -gt 1048576 ] && nfct=1048576
    local hashsize=$(( nfct / 4 )); [ "$hashsize" -lt 16384 ] && hashsize=16384
    local cpus
    cpus=$(nproc 2>/dev/null || echo 1)

    local somax backlog
    if [ "$cpus" -le 1 ]; then
        somax=4096;  backlog=16384
    elif [ "$cpus" -le 4 ]; then
        somax=8192;  backlog=32768
    else
        somax=16384; backlog=65536
    fi

    install -d -m 0755 -o root -g root /etc/sysctl.d

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/10-firewall.conf
    net.ipv4.icmp_echo_ignore_broadcasts = 1
    net.ipv4.icmp_echo_ignore_all = 0
    net.ipv4.tcp_syncookies = 1
    net.ipv4.tcp_max_syn_backlog = 8192
    net.ipv4.tcp_timestamps = 1
    net.ipv4.tcp_rfc1337 = 1
    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    net.ipv4.conf.all.accept_redirects = 0
    net.ipv4.conf.default.accept_redirects = 0
    net.ipv4.conf.all.secure_redirects = 0
    net.ipv4.conf.default.secure_redirects = 0
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    net.ipv4.conf.all.log_martians = 0
    net.ipv4.ip_forward = 1
CONF

    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/18-conntrack.conf
    net.netfilter.nf_conntrack_tcp_loose = 1
    net.netfilter.nf_conntrack_max = ${nfct}
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/22-ephemeral.conf
    net.ipv4.ip_local_port_range = 32768 65535
    net.ipv4.ip_local_reserved_ports = 40000,40001,40002
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/25-mobile.conf
    net.ipv4.tcp_ecn = 2
    net.ipv4.tcp_mtu_probing = 1
    net.ipv4.tcp_slow_start_after_idle = 0
    net.ipv4.tcp_keepalive_time = 60
    net.ipv4.tcp_keepalive_intvl = 15
    net.ipv4.tcp_keepalive_probes = 5
    net.ipv4.tcp_sack = 1
    net.ipv4.tcp_dsack = 1
    net.core.rmem_max = 67108864
    net.core.wmem_max = 67108864
    net.ipv4.tcp_rmem = 4096 262144 33554432
    net.ipv4.tcp_wmem = 4096 262144 33554432
    net.ipv4.tcp_moderate_rcvbuf = 1
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/30-security.conf
    fs.suid_dumpable = 0
    kernel.dmesg_restrict = 1
    kernel.kptr_restrict = 2
    kernel.yama.ptrace_scope = 1
    kernel.core_pattern = /dev/null
    fs.protected_symlinks = 1
    fs.protected_hardlinks = 1
    kernel.randomize_va_space = 2
    kernel.kexec_load_disabled = 1
    kernel.unprivileged_bpf_disabled = 1
CONF

    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/99z-bbr.conf
    net.core.default_qdisc = fq
    net.ipv4.tcp_congestion_control = bbr
    net.core.somaxconn = ${somax}
    net.core.netdev_max_backlog = ${backlog}
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/sysctl.d/99z-firewall.conf
    net.ipv4.conf.all.rp_filter = 2
    net.ipv4.conf.default.rp_filter = 2
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/modules-load.d/nf_conntrack.conf
    nf_conntrack
CONF

    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/modprobe.d/nf_conntrack.conf
    options nf_conntrack hashsize=${hashsize}
CONF

    local files=(
      /etc/sysctl.d/10-firewall.conf
      /etc/sysctl.d/18-conntrack.conf
      /etc/sysctl.d/22-ephemeral.conf
      /etc/sysctl.d/25-mobile.conf
      /etc/sysctl.d/30-security.conf
      /etc/sysctl.d/99z-bbr.conf
      /etc/sysctl.d/99z-firewall.conf
    )
    for conf in "${files[@]}"; do
        sysctl -p -f "${conf}" >/dev/null 2>&1 || true
    done
    if lsmod | grep -q '^nf_conntrack'; then
        update-initramfs -u >/dev/null 2>&1 || true
    fi
}
configure_rps_service() {
    set -euo pipefail

    local host_net_ipv4_public_if_name
    host_net_ipv4_public_if_name="$(ip -4 route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $5}')"
    if [ -z "${host_net_ipv4_public_if_name:-}" ]; then
        host_net_ipv4_public_if_name="$(ip -o link | awk -F': ' '$2 ~ /^(eth|ens|enp)/{print $2; exit}')"
    fi
    if [ -z "${host_net_ipv4_public_if_name:-}" ]; then
        echo "[RPS] skip: no iface detected"
        return 0
    fi

    local queues_dir="/sys/class/net/${host_net_ipv4_public_if_name}/queues"
    if [ ! -d "$queues_dir" ]; then
        echo "[RPS] skip: no queues dir for ${host_net_ipv4_public_if_name}"
        return 0
    fi

    local cpus; cpus="$(nproc 2>/dev/null || echo 1)"
    if [ "$cpus" -lt 2 ]; then
        echo "[RPS] skip: $cpus CPU(s) < 2"
        return 0
    fi

    local rxqs; rxqs="$(ls -d "$queues_dir"/rx-* 2>/dev/null | wc -l || true)"
    if [ "${rxqs:-0}" -ne 1 ]; then
        echo "[RPS] skip: rx-queues=$rxqs (need exactly 1)"
        return 0
    fi

    install -d -m 0755 -o root -g root /usr/local/sbin
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/rps-setup
    #!/bin/bash
    set -Eeuo pipefail
    trap 'rc=$?; logger -p user.err -t rps-setup "failed at line ${LINENO} (rc=${rc})"; exit $rc' ERR

    IF="${1:?usage: rps-setup <ifname>}"
    queues_dir="/sys/class/net/$IF/queues"
    [ -d "$queues_dir" ] || exit 0

    cpus=$(nproc 2>/dev/null || echo 1)
    (( cpus >= 2 )) || exit 0

    mapfile -t rxq_paths < <(ls -d "$queues_dir"/rx-* 2>/dev/null || true)
    rxqs=${#rxq_paths[@]}
    (( rxqs == 1 )) || exit 0

    perq=2048
    global=$(( perq * rxqs ))

    if [[ -w /proc/sys/net/core/rps_sock_flow_entries ]]; then
        printf '%d\n' "$global" > /proc/sys/net/core/rps_sock_flow_entries || true
    fi

    for q in "${rxq_paths[@]}"; do
        f="$q/rps_flow_cnt"
        [[ -w "$f" ]] && printf '%d\n' "$perq" > "$f" || true
    done

    online="$(cat /sys/devices/system/cpu/online)"
    mask=0; IFS=',' read -ra R <<< "$online"
    for r in "${R[@]}"; do
        if [[ "$r" == *-* ]]; then a=${r%-*}; b=${r#*-}; else a=$r; b=$r; fi
        for ((i=a; i<=b && i<64; i++)); do mask=$(( mask | (1<<i) )); done
    done

    dst="$queues_dir/rx-0/rps_cpus"
    [[ -w "$dst" ]] && printf '%x\n' "$mask" > "$dst" || true
CONF

    install -d -m 0755 -o root -g root /etc/systemd/system
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/rps@.service
    [Unit]
    Description=Enable RPS/RFS on %I
    Wants=network-online.target
    After=network-online.target sys-subsystem-net-devices-%i.device
    Requires=sys-subsystem-net-devices-%i.device
    BindsTo=sys-subsystem-net-devices-%i.device
    ConditionPathExists=/sys/class/net/%i

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/rps-setup %i
    RemainAfterExit=yes
    StandardOutput=null
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
CONF

    systemctl daemon-reload
    systemctl enable --now "rps@${host_net_ipv4_public_if_name}.service"

    [ -r /proc/sys/net/core/rps_sock_flow_entries ] && \
        echo "[RPS] rps_sock_flow_entries=$(cat /proc/sys/net/core/rps_sock_flow_entries || true)"

    [ -r "/sys/class/net/${host_net_ipv4_public_if_name}/queues/rx-0/rps_cpus" ] && \
        echo "[RPS] rps_cpus=$(cat /sys/class/net/${host_net_ipv4_public_if_name}/queues/rx-0/rps_cpus || true)"
}
configure_openssh() {
    local host_net_ipv4_public_if_addr="$(LC_ALL=C ip -4 route get 255.255.255.255 2>/dev/null | grep -Po 'src\s+\K([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
    cat <<CONF | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/ssh/sshd_config
    Protocol 2
    MaxSessions 2
    ListenAddress ${host_net_ipv4_public_if_addr}:${host_ssh_port}
    PermitRootLogin no
    PermitTunnel no
    PrintLastLog no
    Compression no
    UsePAM yes
    UseDNS no
    PasswordAuthentication no
    LoginGraceTime 10
    IgnoreRhosts yes
    HostbasedAuthentication no
    AllowGroups $host_user_group deploy
    PermitOpen none
    MaxAuthTries 3
    StrictModes yes
    GatewayPorts no
    MaxStartups 5:30:20
    TCPKeepAlive no
    ClientAliveCountMax 3
    ClientAliveInterval 20
    X11Forwarding no
    AddressFamily inet
    PrintMotd no
    ChallengeResponseAuthentication no
    PermitEmptyPasswords no
    PermitUserEnvironment no
    PermitUserRC no
    RekeyLimit 512M 1h
    AcceptEnv LANG LC_*
    AllowTcpForwarding no
    AllowAgentForwarding no
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    HostKey /etc/ssh/ssh_host_ed25519_key
    HostKeyAlgorithms ssh-ed25519
    Ciphers aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com
    KexAlgorithms sntrup761x25519-sha512@openssh.com
    AuthorizedKeysFile .ssh/authorized_keys
    LogLevel ERROR
    SyslogFacility AUTHPRIV
    Subsystem sftp /bin/false
    Match User deploy
        AuthorizedKeysFile /var/ssh/%u/authorized_keys
        ForceCommand /usr/local/sbin/ssh-guard
        PermitTTY no
        AllowTcpForwarding no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
CONF

    install -d -m 0755 -o root -g root /etc/ssh
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -C ''
    chown root:root /etc/ssh/ssh_host_ed25519_key{,.pub}
    chmod 600 /etc/ssh/ssh_host_ed25519_key
    chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
}
configure_sshd_config_guard() {
    local src_dir="/usr/local/etc/ssh"
    local src_file="$src_dir/sshd_config.golden"
    local guard="/usr/local/sbin/sshd-config-guard"

    install -d -m 0755 -o root -g root "$src_dir"

    if [[ ! -f "$src_file" ]]; then
        install -m 0600 -o root -g root /etc/ssh/sshd_config "$src_file"
    fi

    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin "$guard"
    #!/bin/bash
    set -euo pipefail

    src="/usr/local/etc/ssh/sshd_config.golden"
    dst="/etc/ssh/sshd_config"
    svc="sshd"
    systemctl cat ssh.service >/dev/null 2>&1 && svc="ssh"

    if [[ ! -r "$src" ]]; then
        exit 0
    fi

    tmp="$(mktemp "${dst}.XXXX")"
    cleanup() { rm -f "$tmp"; }
    trap cleanup EXIT

    if ! cmp -s "$src" "$dst"; then
        install -m 0600 -o root -g root "$src" "$tmp"
        sed -i -E '/^\s*Include\s+/d' "$tmp"
        bin="$(command -v sshd || echo /usr/sbin/sshd)"
        if "$bin" -t -f "$tmp"; then
            install -b -m 0600 -o root -g root "$tmp" "$dst"
            systemctl reload "$svc" || systemctl try-restart "$svc" || true
        else
            echo "golden config is invalid; leaving current config untouched" >&2
            exit 1
        fi
    fi
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/sshd-config-guard.service
    [Unit]
    Description=enforce golden /etc/ssh/sshd_config
    Documentation=man:sshd_config(5)
    StartLimitIntervalSec=30s
    StartLimitBurst=10
    
    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/sshd-config-guard
    StandardOutput=null
    StandardError=journal
    Environment=SYSTEMD_PAGER=
    Environment=SYSTEMD_LOG_LEVEL=err
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/sshd-config-guard.path
    [Unit]
    Description=watch /etc/ssh/sshd_config and enforce golden copy
    
    [Path]
    PathChanged=/etc/ssh/sshd_config
    Unit=sshd-config-guard.service
    TriggerLimitIntervalSec=10s
    TriggerLimitBurst=2
    
    [Install]
    WantedBy=paths.target
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/sshd-config-guard.timer
    [Unit]
    Description=periodic sshd-config enforcement

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=1h
    Unit=sshd-config-guard.service

    [Install]
    WantedBy=timers.target
CONF

    systemctl daemon-reload
    systemctl enable --now sshd-config-guard.path
    systemctl enable --now sshd-config-guard.timer
    systemctl start sshd-config-guard.service
}
configure_os_updater() {
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /usr/local/sbin/os-updater
    #!/bin/bash
    set -Eeuo pipefail

    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    exec 9>/run/apt-maint.lock
    if ! flock -n 9; then
        echo "[INFO] another apt run in progress, exiting"
        exit 0
    fi

    trap 'rc=$?; echo "[ERROR] failed at line $LINENO (exit=$rc)"' ERR

    retry() {
        local attempts="$1" 
        local pause="$2" 
        shift 2
        local n=1
        until "$@"; do
            if (( n >= attempts )); then
                echo "[ERROR] after ${attempts} attempts: $*"
                return 1
            fi
            echo "[WARN] attempt $n failed; retrying in ${pause}s: $*"
            sleep "$pause"
            ((n++))
        done
    }

    echo "[INFO] === $(date -Is) start ==="

    apt-get clean
    rm -rf /var/lib/apt/lists/*

    install -d -m 0755 -o root -g root /etc/apt/keyrings || true
    curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/keyrings/docker.gpg || true
    curl -fsSL --proto '=https' --tlsv1.3 https://gvisor.dev/archive.key | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /etc/apt/keyrings/gvisor.gpg || true

    retry 5 10 apt-get -qq -o Acquire::Retries=3 update
    retry 3 20 apt-get -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o DPkg::Lock::Timeout=600 -y dist-upgrade

    apt-get -y autoremove --purge || true
    apt-get clean || true

    need_reboot=false
    reason=""

    current_kernel="$(uname -r || true)"
    latest_installed_kernel="$(ls -1 /lib/modules 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "$latest_installed_kernel" ] && [ "$current_kernel" != "$latest_installed_kernel" ]; then
        need_reboot=true
        reason="kernel $current_kernel -> $latest_installed_kernel"
    fi

    if [ -f /run/reboot-required ] || [ -f /var/run/reboot-required ]; then
        need_reboot=true
        if [ -z "$reason" ]; then
            reason="reboot-required flag"
        else
            reason="$reason + reboot-required flag"
        fi
    fi

    if $need_reboot; then
        echo "[INFO] rebooting: $reason"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reboot || /sbin/reboot
        else
            /sbin/reboot
        fi
    else
        echo "[INFO] reboot not required"
    fi

    echo "[INFO] === $(date -Is) end ==="
CONF

    chmod 0755 /usr/local/sbin/os-updater
    chown root:root /usr/local/sbin/os-updater

    install -o root -g adm -m 0640 /dev/null /var/log/apt-auto-upgrade.log

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/os-updater.service
    [Unit]
    Description=Safe unattended apt dist-upgrade (kernel-aware)
    Documentation=man:apt-get(8)
    After=network-online.target apt-daily.service apt-daily-upgrade.service
    Wants=network-online.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/os-updater
    Nice=10
    TimeoutStartSec=2h
    Environment=DEBIAN_FRONTEND=noninteractive
    Environment=APT_LISTCHANGES_FRONTEND=none
    StandardOutput=append:/var/log/apt-auto-upgrade.log
    StandardError=append:/var/log/apt-auto-upgrade.log
    UMask=0027

    [Install]
    WantedBy=multi-user.target
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/os-updater.timer
    [Unit]
    Description=Run os_updater nightly

    [Timer]
    OnCalendar=*-*-* 01:00
    RandomizedDelaySec=13m
    Persistent=true
    AccuracySec=1h

    [Install]
    WantedBy=timers.target
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/logrotate.d/os_updater
    /var/log/apt-auto-upgrade.log {
      daily
      rotate 8
      size 512k
      compress
      delaycompress
      dateext
      missingok
      notifempty
      create 0640 root adm
      su root adm
    }
CONF

    systemctl daemon-reload
    systemctl enable --now os-updater.timer
}
setup_matrix_updater_service() {
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/matrix-updater
    #!/bin/bash
    set -Eeuo pipefail

    base_image_tun="debian:trixie-slim"
    compose_file="/opt/matrix/data/docker-compose.yaml"
    compose_proj="matrix"
    volumes_file="/opt/matrix/data/.volumes"
    env_file="/opt/matrix/data/.env"

    prod_net_internal="matrix_internal"
    prod_net_external="matrix_external"

    alpine_img="alpine:latest"

    ctr_syn_prod="matrix_synapse"
    ctr_pg_prod="matrix_postgres"
    ctr_redis_prod="matrix_redis"
    ctr_tun_prod="matrix_tunnel"

    log_i() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
    log_e() { printf "\033[1;31m[ERR]\033[0m %s\n" "$*" >&2; }
    die() { log_e "$*"; exit 1; }

    need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
    compose_config() { docker compose -f "$compose_file" config; }

    get_image_of_service() {
        local svc="$1"
        compose_config | awk -v svc="$svc" '$0 ~ ("^[[:space:]]*" svc ":") { f=1; next } f && $1=="image:" { print $2; exit }'
    }

    pull_image() {
        local img="$1"
        docker pull "$img" >/dev/null
        docker image inspect -f '{{.Id}}' "$img"
    }

    current_ctr_image_id() {
        local ctr="$1"
        docker inspect -f '{{.Image}}' "$ctr" 2>/dev/null || true
    }

    img_changed() {
        local cur="$1" new="$2"
        [[ -n "$cur" && -n "$new" && "$cur" == "$new" ]] && echo 0 || echo 1
    }

    rand() { od -An -N3 -tu4 < /dev/urandom | tr -d '[:space:]'; }

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

    prune_repo_unused() {
        local repo="$1" keep_ref="$2"
        docker images --format '{{.Repository}}:{{.Tag}}' \
        | awk -v r="^${repo}:" '$0 ~ r {print}' \
        | while read -r ref; do
            [[ "$ref" == "$keep_ref" ]] && continue
            if ! docker ps -aq --filter "ancestor=$ref" | grep -q .; then
                docker rmi -f "$ref" >/dev/null 2>&1 || true
            fi
        done
    }

    rm_if_unused_image() {
        local ref="$1"
        if docker image inspect "$ref" >/dev/null 2>&1; then
            if ! docker ps -a --filter "ancestor=$ref" -q | grep -q .; then
                docker image rm -f "$ref" >/dev/null 2>&1 || true
            fi
        fi
    }

    sweep_leftovers() {
        docker ps -aq --filter 'name=^matrix_(postgres|redis|synapse)_canary_[0-9]+$' | xargs -r docker rm -f >/dev/null 2>&1 || true
        docker ps -aq --filter 'name=^matrix_tunnel_probe_[0-9]+$' | xargs -r docker rm -f >/dev/null 2>&1 || true
        docker volume ls --format '{{.Name}}' | grep -E '^matrix_(synapse|postgres)_stage_[0-9]+$' | xargs -r docker volume rm -f >/dev/null 2>&1 || true
        for v in $(docker volume ls -q | grep -E '^[0-9a-f]{64}$' || true); do
            docker ps -aq --filter "volume=$v" | grep -q . || docker volume rm -f "$v" >/dev/null 2>&1 || true
        done
    }

    backup_lines=()

    add_backup_line() {
        local svc="$1" repo_tag="$2" old_id="$3"
        [[ -n "$old_id" ]] && backup_lines+=( "${svc}|${repo_tag}|${old_id}" )
    }

    rollback_to_backups() {
        if ((${#backup_lines[@]}==0)); then
            log_e "no backups captured; cannot rollback"
            return 1
        fi
        log_i "retagging previous images to original repo:tag…"
        local line svc repo_tag old_id
        for line in "${backup_lines[@]}"; do
            IFS='|' read -r svc repo_tag old_id <<<"$line"
            docker image tag "$old_id" "$repo_tag"
        done
        log_i "rolling back production to previous images…"
        docker compose -f "$compose_file" -p "$compose_proj" up -d --force-recreate
        wait_health "$ctr_pg_prod" 120 || log_e "postgres may be unhealthy after rollback"
        wait_health "$ctr_syn_prod" 180 || log_e "synapse may be unhealthy after rollback"
        wait_health "$ctr_tun_prod" 120 || true
        wait_health "$ctr_redis_prod" 90 || true
        log_i "rollback complete."
    }

    probe_tunnel() {
        local name="matrix_tunnel_probe_$(rand)"
        timeout 20s docker run --rm --name "$name" \
            --network "${prod_net_internal}" \
            -v "matrix_tunnel:/ssh:ro" \
            "$img_tun_tag" \
            ssh -q -F /ssh/config -o BatchMode=yes -o ConnectTimeout=5 -O check proxy
    }

    tmp_dir=""
    stage_marks=()
    canary_compose=""
    canary_proj=""

    cleanup() {
        set +e
        if [[ -n "$canary_compose" && -f "$canary_compose" && -n "$canary_proj" ]]; then
            docker compose -f "$canary_compose" -p "$canary_proj" down >/dev/null 2>&1 || true
        fi
        for m in "${stage_marks[@]}"; do
            case "$m" in
                tmp:*)  rm -rf "${m#tmp:}" ;;
                file:*) rm -f "${m#file:}" ;;
                vol:*)  docker volume rm -f "${m#vol:}" >/dev/null 2>&1 || true ;;
            esac
        done
        sweep_leftovers
    }
    trap cleanup EXIT

    need_cmd docker
    need_cmd awk
    need_cmd sed
    need_cmd base64
    need_cmd od
    need_cmd tr
    need_cmd flock
    need_cmd timeout
    need_cmd grep
    need_cmd xargs

    [[ -f "$compose_file" ]] || die "compose file not found: $compose_file"
    docker compose -f "$compose_file" config -q || die "compose syntax error"
    [[ -f "$volumes_file" ]] || die "volumes bundle not found: $volumes_file"
    [[ -f "$env_file" ]] || die "env file not found: $env_file"

    set -a
    . "$env_file"
    set +a

    exec 9>/run/matrix-updater.lock
    if ! flock -n 9; then
        log_i "another update run is in progress, exiting"
        exit 0
    fi

    docker pull "$alpine_img" >/dev/null || true
    sweep_leftovers

    log_i "resolving images…"
    img_syn="$(get_image_of_service synapse)"; [[ -n "$img_syn" ]] || die "image for synapse not found"
    img_pg="$(get_image_of_service postgres)"; [[ -n "$img_pg" ]] || die "image for postgres not found"
    img_redis="$(get_image_of_service redis)"; [[ -n "$img_redis" ]] || die "image for redis not found"
    img_tun_tag="$(get_image_of_service tunnel)"; [[ -n "$img_tun_tag" ]] || die "image for tunnel not found"

    log_i "pulling registry images…"
    id_syn_new="$(pull_image "$img_syn")"
    id_pg_new="$(pull_image "$img_pg")"
    id_redis_new="$(pull_image "$img_redis")"

    log_i "checking tunnel base image ${base_image_tun}…"
    id_tun_base_old="$(docker image inspect -f '{{.Id}}' "$base_image_tun" 2>/dev/null || true)"
    docker pull "$base_image_tun" >/dev/null 2>&1 || true
    id_tun_base_new="$(docker image inspect -f '{{.Id}}' "$base_image_tun" 2>/dev/null || true)"

    changed_tun_base=0
    if [[ -z "$id_tun_base_old" || -z "$id_tun_base_new" || "$id_tun_base_old" != "$id_tun_base_new" ]]; then
        changed_tun_base=1
        log_i "tunnel base image changed; building tunnel image…"
        docker compose -f "$compose_file" -p "$compose_proj" build tunnel >/dev/null || true
    else
        log_i "tunnel base image unchanged; skipping tunnel build"
    fi

    id_syn_cur="$(current_ctr_image_id "$ctr_syn_prod")"
    id_pg_cur="$(current_ctr_image_id "$ctr_pg_prod")"
    id_redis_cur="$(current_ctr_image_id "$ctr_redis_prod")"
    id_tun_cur="$(current_ctr_image_id "$ctr_tun_prod")"

    changed_syn="$(img_changed "$id_syn_cur" "$id_syn_new")"
    changed_pg="$(img_changed "$id_pg_cur" "$id_pg_new")"
    changed_redis="$(img_changed "$id_redis_cur" "$id_redis_new")"
    changed_tun="$changed_tun_base"

    if [[ "$changed_syn" -eq 0 && "$changed_pg" -eq 0 && "$changed_redis" -eq 0 && "$changed_tun" -eq 0 ]]; then
        log_i "images unchanged; nothing to do"
        exit 0
    fi

    [[ "$changed_pg" -eq 1 && -n "$id_pg_cur" ]] && add_backup_line "postgres" "$img_pg" "$id_pg_cur"
    [[ "$changed_redis" -eq 1 && -n "$id_redis_cur" ]] && add_backup_line "redis" "$img_redis" "$id_redis_cur"
    [[ "$changed_syn" -eq 1 && -n "$id_syn_cur" ]] && add_backup_line "synapse" "$img_syn" "$id_syn_cur"
    [[ "$changed_tun" -eq 1 && -n "$id_tun_cur" ]] && add_backup_line "tunnel" "$img_tun_tag" "$id_tun_cur"

    run_canary=0
    (( changed_syn == 1 || changed_pg == 1 )) && run_canary=1

    if [[ "$run_canary" -eq 1 ]]; then
        log_i "stopping production stack (keep networks)…"
        docker stop "$ctr_pg_prod" "$ctr_redis_prod" "$ctr_syn_prod" "$ctr_tun_prod" >/dev/null 2>&1 || true
        docker rm -f "$ctr_pg_prod" "$ctr_redis_prod" "$ctr_syn_prod" "$ctr_tun_prod" >/dev/null 2>&1 || true

        tmp_dir="$(mktemp -d -t matrix-canary.XXXXXXXX)"; stage_marks+=("tmp:${tmp_dir}")

        b64_syn="$(sed -n 's/^volume_synapse="\([^"]*\)".*/\1/p' "$volumes_file" || true)"
        b64_pg="$(sed -n 's/^volume_postgres="\([^"]*\)".*/\1/p' "$volumes_file" || true)"
        [[ -n "$b64_syn" && -n "$b64_pg" ]] || die "invalid .volumes: missing volume_synapse/volume_postgres"

        printf '%s' "$b64_syn" | base64 -d > "${tmp_dir}/synapse.tar.xz"
        printf '%s' "$b64_pg" | base64 -d > "${tmp_dir}/postgres.tar.xz"

        vol_syn_stage="matrix_synapse_stage_$(rand)"
        vol_pg_stage="matrix_postgres_stage_$(rand)"
        ctr_syn_canary="matrix_synapse_canary_$(rand)"
        ctr_pg_canary="matrix_postgres_canary_$(rand)"
        ctr_redis_canary="matrix_redis_canary_$(rand)"

        docker volume create "$vol_syn_stage" >/dev/null
        docker volume create "$vol_pg_stage" >/dev/null
        stage_marks+=("vol:${vol_syn_stage}" "vol:${vol_pg_stage}")

        docker run --rm -v "${vol_syn_stage}:/data" -v "${tmp_dir}:/in:ro" "$alpine_img" \
            sh -c "apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf /in/synapse.tar.xz -C /data"
        docker run --rm -v "${vol_pg_stage}:/var/lib/postgresql/data" -v "${tmp_dir}:/in:ro" "$alpine_img" \
            sh -c "apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf /in/postgres.tar.xz -C /var/lib/postgresql/data"

        canary_proj="matrix_canary_$(rand)"
        canary_compose="$(mktemp -t matrix-canary-compose.XXXXXXXX.yaml)"; stage_marks+=("file:${canary_compose}")

        cat >"$canary_compose" <<YAML
    services:
      postgres:
        image: ${img_pg}
        container_name: ${ctr_pg_canary}
        hostname: postgres
        restart: unless-stopped
        logging: { driver: "none" }
        healthcheck:
          test: ["CMD","pg_isready","-h","localhost","-p","5432"]
          interval: 5s
          timeout: 3s
          retries: 30
        volumes: [ "pg_stage:/var/lib/postgresql" ]
        networks:
          matrix_internal:
            ipv4_address: ${docker_internal_postgres_ipv4}
        runtime: runsc

      redis:
        image: ${img_redis}
        container_name: ${ctr_redis_canary}
        hostname: redis
        restart: unless-stopped
        logging: { driver: "none" }
        tmpfs: [ "/data:size=128m,mode=0700,noexec,nosuid,nodev" ]
        command: ["redis-server","--save","","--appendonly","no","--maxmemory","128mb","--maxmemory-policy","allkeys-lru","--loglevel","warning"]
        healthcheck:
          test: ["CMD","redis-cli","ping"]
          interval: 3s
          timeout: 2s
          retries: 30
        networks:
          matrix_internal:
            ipv4_address: ${docker_internal_redis_ipv4}
        runtime: runsc

      synapse:
        image: ${img_syn}
        container_name: ${ctr_syn_canary}
        hostname: synapse
        user: "991:991"
        restart: unless-stopped
        logging: { driver: "none" }
        environment:
          - SYNAPSE_CONFIG_PATH=/data/homeserver.yaml
          - SYNAPSE_REPORT_STATS=no
        healthcheck:
          test: ["CMD","curl","-fsS","http://127.0.0.1:8008/health"]
          interval: 5s
          timeout: 3s
          retries: 60
        depends_on:
          postgres: { condition: service_healthy }
          redis: { condition: service_healthy }
        volumes: [ "syn_stage:/data" ]
        networks:
          matrix_internal:
            ipv4_address: ${docker_internal_synapse_ipv4}
          matrix_external:
            ipv4_address: ${docker_external_synapse_ipv4}
        runtime: runsc

    networks:
      matrix_internal:
        name: ${prod_net_internal}
        external: true
      matrix_external:
        name: ${prod_net_external}
        external: true

    volumes:
      pg_stage:  { name: ${vol_pg_stage}, external: true }
      syn_stage: { name: ${vol_syn_stage}, external: true }
    YAML

        log_i "starting canary stack…"
        docker compose -f "$canary_compose" -p "$canary_proj" up -d --force-recreate

        log_i "waiting for Postgres (canary)…"
        if ! wait_health "$ctr_pg_canary" 120; then
            log_e "canary postgres failed — rolling back prod"
            docker compose -f "$canary_compose" -p "$canary_proj" down || true
            rollback_to_backups || true
            exit 1
        fi

        log_i "waiting for Synapse (canary)…"
        if ! wait_health "$ctr_syn_canary" 180; then
            log_e "canary synapse failed — rolling back prod"
            docker compose -f "$canary_compose" -p "$canary_proj" down || true
            rollback_to_backups || true
            exit 1
        fi

        log_i "canary passed. shutting down canary…"
        docker compose -f "$canary_compose" -p "$canary_proj" down

        log_i "starting production with new images…"
        docker compose -f "$compose_file" -p "$compose_proj" up -d
        wait_health "$ctr_pg_prod" 120 || die "postgres unhealthy after rollout"
        wait_health "$ctr_syn_prod" 180 || die "synapse unhealthy after rollout"
        wait_health "$ctr_redis_prod" 90 || true
        wait_health "$ctr_tun_prod" 120 || true
    else
        log_i "rolling production (minimal changes)…"

        if [[ "$changed_pg" -eq 1 ]]; then
            docker compose -f "$compose_file" -p "$compose_proj" up -d --no-deps --no-build postgres
            wait_health "$ctr_pg_prod" 120 || die "postgres unhealthy after rollout"
            need_restart_synapse=1
        fi

        if [[ "$changed_redis" -eq 1 ]]; then
            docker compose -f "$compose_file" -p "$compose_proj" up -d --no-deps --no-build redis
            wait_health "$ctr_redis_prod" 90 || die "redis unhealthy after rollout"
        fi

        if [[ "$changed_syn" -eq 1 || "${need_restart_synapse:-0}" -eq 1 ]]; then
            docker compose -f "$compose_file" -p "$compose_proj" up -d --no-deps --no-build synapse
            wait_health "$ctr_syn_prod" 180 || die "synapse unhealthy after rollout"
        fi

        if [[ "$changed_tun" -eq 1 ]]; then
            log_i "probing tunnel image…"
            probe_tunnel || { log_e "tunnel probe failed — rolling back"; rollback_to_backups || true; exit 1; }
            docker compose -f "$compose_file" -p "$compose_proj" up -d --no-deps --no-build tunnel
            wait_health "$ctr_tun_prod" 120 || die "tunnel unhealthy after rollout"
        fi
    fi

    syn_repo="${img_syn%:*}"
    pg_repo="${img_pg%:*}"
    redis_repo="${img_redis%:*}"
    tun_repo="${img_tun_tag%:*}"
    prune_repo_unused "$syn_repo" "$img_syn"
    prune_repo_unused "$pg_repo" "$img_pg"
    prune_repo_unused "$redis_repo" "$img_redis"
    prune_repo_unused "$tun_repo" "$img_tun_tag"

    rm_if_unused_image "$alpine_img"
    docker image prune -f >/dev/null 2>&1 || true
    docker builder prune -f >/dev/null 2>&1 || true

    sweep_leftovers
    log_i "update complete."
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/matrix-updater.service
    [Unit]
    Description=Update matrix docker images
    After=network-online.target docker.service
    Wants=network-online.target docker.service

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/matrix-updater
    TimeoutStartSec=30m
    Nice=10
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/matrix-updater.timer
    [Unit]
    Description=Run matrix-updater nightly at 02:00

    [Timer]
    OnCalendar=*-*-* 01:30
    Persistent=true
    AccuracySec=1min

    [Install]
    WantedBy=timers.target
CONF

    systemctl daemon-reload
    systemctl enable --now matrix-updater.timer
}
setup_wipe_service() {
    install -d -m 0750 -o root -g root /var/lib/wipe
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/wipe
    #!/bin/bash
    set -Eeuo pipefail

    compose_file="/opt/matrix/data/docker-compose.yaml"
    compose_proj="matrix"
    data_dir="/opt/matrix/data"
    vol_file="${data_dir}/.volumes"

    vol_syn_name="matrix_synapse"
    vol_pg_name="matrix_postgres"
    vol_tun_name="matrix_tunnel"
    vol_redis_name="matrix_redis"

    ctr_syn_name="matrix_synapse"
    ctr_pg_name="matrix_postgres"

    log_i() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
    log_e() { printf "\033[1;31m[ERR]\033[0m %s\n" "$*" >&2; }
    die() { log_e "$*"; exit 1; }

    need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

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

    rm_if_unused_image() {
        local ref="$1"
        if docker image inspect "$ref" >/dev/null 2>&1; then
            if ! docker ps -a --filter "ancestor=$ref" -q | grep -q .; then
                docker image rm -f "$ref" >/dev/null 2>&1 || true
            fi
        fi
    }

    tmp_dir=""
    cleanup() {
        set +e
        [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT

    need_cmd docker
    need_cmd sed
    need_cmd base64
    need_cmd flock

    [[ -f "$compose_file" ]] || die "compose file not found: $compose_file"
    docker compose -f "$compose_file" -p "$compose_proj" config -q || die "compose syntax error"
    [[ -f "$vol_file" ]] || die ".volumes not found: $vol_file"

    exec 9>/run/matrix-restore.lock
    if ! flock -n 9; then
        log_i "another restore run is in progress, exiting"
        exit 0
    fi

    b64_syn="$(sed -n 's/^volume_synapse="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    b64_pg="$(sed -n 's/^volume_postgres="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    b64_tun="$(sed -n 's/^volume_tunnel="\([^"]*\)".*/\1/p' "$vol_file" || true)"

    [[ -n "$b64_syn" && -n "$b64_pg" ]] || die "missing volume payloads in .volumes"

    tmp_dir="$(mktemp -d -t matrix-restore.XXXXXXXX)"
    printf '%s' "$b64_syn" | base64 -d > "${tmp_dir}/synapse.tar.xz"
    printf '%s' "$b64_pg"  | base64 -d > "${tmp_dir}/postgres.tar.xz"
    [[ -z "$b64_tun" ]] || printf '%s' "$b64_tun" | base64 -d > "${tmp_dir}/tunnel.tar.xz"

    log_i "stopping stack…"
    docker compose -f "$compose_file" -p "$compose_proj" down || true

    log_i "recreating volumes…"
    docker volume rm -f "$vol_syn_name" "$vol_pg_name" "$vol_tun_name" "$vol_redis_name" >/dev/null 2>&1 || true
    docker volume create "$vol_syn_name" >/dev/null
    docker volume create "$vol_pg_name" >/dev/null
    docker volume create "$vol_tun_name" >/dev/null

    log_i "restoring synapse volume…"
    docker run --rm \
        -v "${vol_syn_name}:/data" \
        -v "${tmp_dir}:/backup:ro" \
        alpine:latest sh -c 'apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf /backup/synapse.tar.xz -C /data'

    log_i "restoring postgres volume…"
    docker run --rm \
        -v "${vol_pg_name}:/var/lib/postgresql/data" \
        -v "${tmp_dir}:/backup:ro" \
        alpine:latest sh -c 'apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf /backup/postgres.tar.xz -C /var/lib/postgresql/data'

    if [[ -n "$b64_tun" ]]; then
        log_i "restoring tunnel volume…"
        docker run --rm \
            -v "${vol_tun_name}:/ssh" \
            -v "${tmp_dir}:/backup:ro" \
            alpine:latest sh -c 'apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf /backup/tunnel.tar.xz -C /ssh'
    else
        log_i "no tunnel backup in .volumes — tunnel volume recreated empty"
    fi

    log_i "starting stack…"
    docker compose -f "$compose_file" -p "$compose_proj" up -d --force-recreate

    log_i "waiting for Postgres…"
    wait_health "$ctr_pg_name" 120 || die "postgres unhealthy after restore"

    log_i "waiting for Synapse…"
    wait_health "$ctr_syn_name" 180 || die "synapse unhealthy after restore"

    rm_if_unused_image alpine:latest

    log_i "restore complete"
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/wipe.service
    [Unit]
    Description=Wipe matrix volumes
    After=network.target
    Wants=network.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/wipe

    [Install]
    WantedBy=multi-user.target
CONF

    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/wipe-gate-utc
    #!/bin/bash
    set -euo pipefail
    
    log_e() {
        echo "[wipe-gate] ERROR: $*" >&2
    }
    
    install -d -m 0750 -o root -g root /var/lib/wipe
    anchor_file="/var/lib/wipe/anchor_utc_day"
    lockfile="/run/wipe-gate.lock"

    exec 9> "$lockfile" || true
    if ! flock -n 9; then
        exit 0
    fi
    
    today_days=$(( $(date -u -d "$(date -u +%F) 00:00" +%s) / 86400 ))
    
    if [[ ! -f "$anchor_file" ]]; then
        echo "$today_days" > "$anchor_file"
        exit 0
    fi
    
    anchor_days=$(cat "$anchor_file")
    delta=$(( today_days - anchor_days ))
    
    if (( delta % 2 == 0 )); then
        if ! /usr/bin/systemctl start --wait wipe.service; then
            rc=$?
            log_e "failed to start wipe.service rc=$rc"
            /usr/bin/systemctl status --no-pager --full wipe.service >&2 || true
            /usr/bin/journalctl -u wipe.service -n 50 --no-pager >&2 || true
            exit "$rc"
        fi
    fi
    
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/wipe-gate-utc.service
    [Unit]
    Description=Gate to start wipe.service every other day at 02:00 UTC
    Wants=network-online.target
    After=network-online.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/wipe-gate-utc
    SuccessExitStatus=0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/wipe-gate-utc.timer
    [Unit]
    Description=Run gate for wipe.service daily at 02:00 UTC

    [Timer]
    Unit=wipe-gate-utc.service
    OnCalendar=*-*-* 02:00:00 UTC
    Persistent=yes
    AccuracySec=1min
    WakeSystem=yes

    [Install]
    WantedBy=timers.target
CONF

    systemctl daemon-reload
    systemctl enable --now wipe-gate-utc.timer
    systemctl start wipe-gate-utc.service
}
setup_build_service() {
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/build
    #!/bin/bash
    # Build new Matrix release with volume restore from volumes
    # WARNING: nukes ALL Docker resources system-wide before deploy.
    
    set -Eeuo pipefail
    IFS=$'\n\t'
    umask 077
    
    project_path="/opt/matrix"
    project_dir="${project_path}/data"
    compose_file="${project_dir}/docker-compose.yaml"
    deploy_dir="${project_path}/deploy/release"
    compose_proj="matrix"
    
    # volumes & containers
    vol_file="${project_dir}/.volumes"
    vol_syn_name="matrix_synapse"
    vol_pg_name="matrix_postgres"
    vol_tun_name="matrix_tunnel"
    
    ctr_syn_name="matrix_synapse"
    ctr_pg_name="matrix_postgres"
    ctr_redis_name="matrix_redis"
    ctr_tunnel_name="matrix_tunnel"
    
    net_name="matrix"
    
    log_i() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
    log_e() { printf "\033[1;31m[ERR]\033[0m %s\n" "$*" >&2; }
    die() { log_e "$*"; exit 1; }
    
    need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
    
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
    
    rm_if_unused_image() {
        local ref="$1"
        if docker image inspect "$ref" >/dev/null 2>&1; then
            if ! docker ps -a --filter "ancestor=$ref" -q | grep -q .; then
                docker image rm -f "$ref" >/dev/null 2>&1 || true
            fi
        fi
    }
    
    compose_config() {
        docker compose -f "$compose_file" -p "$compose_proj" config
    }
    
    get_image_of_service() {
        local svc="$1"
        compose_config | awk -v svc="$svc" '$0 ~ ("^[[:space:]]*" svc ":") { f=1; next } f && $1=="image:" { print $2; exit }'
    }
    
    restore_volume_from_tarxz() {
        local vol_name="$1" tarxz="$2" dest="$3"
        docker run --rm \
            -v "${vol_name}:${dest}" \
            -v "${tarxz%/*}:/backup:ro" \
            alpine:latest sh -c 'apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf "/backup/'"$(basename "$tarxz")"'" -C "'"$dest"'"'
    }
    
    tmp_dir=""
    cleanup() { set +e; [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir" >/dev/null 2>&1 || true; }
    trap cleanup EXIT
    
    need_cmd docker; need_cmd tar; need_cmd base64; need_cmd sed; need_cmd awk; need_cmd flock; need_cmd xargs; need_cmd grep
    
    exec 9>/run/matrix-deploy.lock
    if ! flock -n 9; then
        log_i "another deploy run is in progress, exiting"
        exit 0
    fi
    
    archive="$(ls -1t "${deploy_dir}"/*.tar.xz 2>/dev/null | head -n1 || true)"
    [[ -n "$archive" ]] || { log_i "no archives in ${deploy_dir}, nothing to do"; exit 0; }
    
    log_i "stopping current stack…"
    docker compose -f "$compose_file" -p "$compose_proj" down --remove-orphans || true
    docker rm -f "$ctr_syn_name" "$ctr_pg_name" "$ctr_redis_name" "$ctr_tunnel_name" >/dev/null 2>&1 || true
    docker network rm "$net_name" >/dev/null 2>&1 || true
    
    log_i "NUKE ALL: removing ALL Docker resources system-wide (containers, images, volumes, networks, cache)…"
    docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker volume ls -q | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    docker network ls --format '{{.Name}}' | grep -Ev '^(bridge|host|none)$' | xargs -r docker network rm >/dev/null 2>&1 || true
    docker images -aq | xargs -r docker image rm -f >/dev/null 2>&1 || true
    docker builder prune -af >/dev/null 2>&1 || true
    docker system prune -af --volumes >/dev/null 2>&1 || true
    
    log_i "deploying new data/ from $(basename "$archive")…"
    [[ -d "$project_dir" ]] && rm -rf "$project_dir"
    tar -xJf "$archive" -C "$project_path"
    
    [[ -f "$compose_file" ]] || die "compose file not found after extract: $compose_file"
    [[ -f "$vol_file" ]] || die ".volumes not found after extract: $vol_file"
    docker compose -f "$compose_file" -p "$compose_proj" config -q || die "compose syntax error"
    
    # pull/build images fresh
    img_syn="$(get_image_of_service synapse)"; [[ -n "$img_syn" ]] || die "image for synapse not found"
    img_pg="$(get_image_of_service postgres)"; [[ -n "$img_pg" ]] || die "image for postgres not found"
    img_redis="$(get_image_of_service redis)"; [[ -n "$img_redis" ]] || die "image for redis not found"
    
    log_i "pulling registry images…"
    docker pull "$img_syn" >/dev/null
    docker pull "$img_pg" >/dev/null
    docker pull "$img_redis" >/dev/null
    
    log_i "building local images (if any, e.g. tunnel)…"
    docker compose -f "$compose_file" -p "$compose_proj" build --pull >/dev/null || true
    
    # read backups
    b64_syn="$(sed -n 's/^volume_synapse="\([^"]*\)".*/\1/p'  "$vol_file" || true)"
    b64_pg="$(sed -n 's/^volume_postgres="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    b64_tun="$(sed -n 's/^volume_tunnel="\([^"]*\)".*/\1/p'  "$vol_file" || true)"
    
    [[ -n "$b64_syn" && -n "$b64_pg" ]] || die "missing base64 payloads (synapse/postgres) in .volumes"
    if [[ -z "$b64_tun" ]]; then
        log_i "no 'volume_tunnel' in .volumes — skipping tunnel restore"
    fi
    
    tmp_dir="$(mktemp -d -t matrix-deploy.XXXXXXXX)"
    printf '%s' "$b64_syn" | base64 -d > "${tmp_dir}/synapse.tar.xz"
    printf '%s' "$b64_pg" | base64 -d > "${tmp_dir}/postgres.tar.xz"
    [[ -z "$b64_tun" ]] || printf '%s' "$b64_tun" | base64 -d > "${tmp_dir}/tunnel.tar.xz"
    
    log_i "recreating volumes…"
    docker volume rm -f "$vol_syn_name" "$vol_pg_name" "$vol_tun_name" "matrix_redis" >/dev/null 2>&1 || true
    docker volume create "$vol_syn_name" >/dev/null
    docker volume create "$vol_pg_name"  >/dev/null
    docker volume create "$vol_tun_name" >/dev/null
    
    log_i "restoring volumes from .volumes…"
    restore_volume_from_tarxz "$vol_syn_name" "${tmp_dir}/synapse.tar.xz"  "/data"
    restore_volume_from_tarxz "$vol_pg_name"  "${tmp_dir}/postgres.tar.xz" "/var/lib/postgresql/data"
    [[ -z "$b64_tun" ]] || restore_volume_from_tarxz "$vol_tun_name" "${tmp_dir}/tunnel.tar.xz"  "/ssh"
    
    log_i "starting new stack…"
    docker compose -f "$compose_file" -p "$compose_proj" up -d --force-recreate
    
    log_i "waiting for Postgres…"
    wait_health "$ctr_pg_name" 120 || die "postgres unhealthy after deploy"
    
    log_i "waiting for Synapse…"
    wait_health "$ctr_syn_name" 180 || die "synapse unhealthy after deploy"
    
    rm_if_unused_image "alpine:latest"
    docker image prune -f  >/dev/null 2>&1 || true
    docker builder prune -f >/dev/null 2>&1 || true
    
    log_i "deploy complete."
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/build.service
    [Unit]
    Description=Build (runs a single script)
    Wants=network-online.target
    After=network-online.target
    
    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/build
    RemainAfterExit=no
    
    [Install]
    WantedBy=multi-user.target
CONF

    systemctl daemon-reload
}
setup_restore_service() {
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/restore
    #!/bin/bash
    set -Eeuo pipefail
    umask 077
    
    project_path="/opt/matrix"
    project_dir="${project_path}/data"
    backup_dir="${project_path}/deploy/backup"
    release_dir="${project_path}/deploy/release"
    compose_file="${project_dir}/docker-compose.yaml"
    compose_proj="matrix"
    vol_file="${project_dir}/.volumes"
    
    vol_syn_name="matrix_synapse"
    vol_pg_name="matrix_postgres"
    vol_redis_name="matrix_redis"
    vol_tun_name="matrix_tunnel"
    
    ctr_syn_name="matrix_synapse"
    ctr_pg_name="matrix_postgres"
    ctr_redis_name="matrix_redis"
    ctr_tun_name="matrix_tunnel"
    
    net_name="matrix"
    alpine_img="alpine:3.20"
    
    log_i() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
    log_e() { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }
    die() { log_e "$*"; exit 1; }
    need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
    
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
    
    rm_if_unused_image() {
        local ref="$1"
        if docker image inspect "$ref" >/dev/null 2>&1; then
            if ! docker ps -a --filter "ancestor=$ref" -q | grep -q .; then
                docker image rm -f "$ref" >/dev/null 2>&1 || true
            fi
        fi
    }
    
    compose_config() { 
        docker compose -f "$compose_file" -p "$compose_proj" config
    }

    get_image_of_service() {
        local svc="$1"
        compose_config | awk -v svc="$svc" '$0 ~ ("^[[:space:]]*" svc ":") { f=1; next } f && $1=="image:" { print $2; exit }'
    }
    
    pull_from_compose() {
        local img
        img="$(get_image_of_service postgres)"; [[ -n "$img" ]] && docker pull "$img" >/dev/null || true
        img="$(get_image_of_service redis)"; [[ -n "$img" ]] && docker pull "$img" >/dev/null || true
        img="$(get_image_of_service synapse)"; [[ -n "$img" ]] && docker pull "$img" >/dev/null || true
    }
    
    restore_volume_from_tarxz() {
        local vol_name="$1" tarxz="$2" dest="$3"
        docker run --rm \
            -v "${vol_name}:${dest}" \
            -v "${tarxz%/*}:/backup:ro" \
            "$alpine_img" sh -c 'apk add --no-cache xz >/dev/null 2>&1 || true; tar -xJf "/backup/'"$(basename "$tarxz")"'" -C "'"$dest"'"'
    }
    
    tmp_dir=""
    cleanup() {
        set +e
        [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT
    
    need_cmd docker
    need_cmd tar
    need_cmd sed
    need_cmd base64
    need_cmd flock
    
    exec 9>/run/matrix-restore-backup.lock
    if ! flock -n 9; then
        log_i "another restore-backup run is in progress, exiting"
        exit 0
    fi
    
    archive="$(ls -1t "${backup_dir}"/*.tar.xz 2>/dev/null | head -n1 || true)"
    [[ -n "$archive" ]] || { log_e "no backup archives in ${backup_dir}"; exit 1; }
    
    log_i "stopping stack…"
    if [[ -f "$compose_file" ]]; then
        docker compose -f "$compose_file" -p "$compose_proj" down || true
    fi
    docker rm -f "$ctr_syn_name" "$ctr_pg_name" "$ctr_redis_name" "$ctr_tun_name" >/dev/null 2>&1 || true
    docker network rm "$net_name" >/dev/null 2>&1 || true
    
    log_i "refreshing release/ from backup…"
    mkdir -p "$release_dir"
    rm -rf "${release_dir:?}/"*
    cp -a "$archive" "$release_dir/"
    
    log_i "deploying data/ from $(basename "$archive")…"
    cd "$project_path"
    rm -rf "$project_dir"
    tar -xJf "${release_dir}/$(basename "$archive")" -C "$project_path"
    
    [[ -f "$compose_file" ]] || die "compose file not found after extract: $compose_file"
    docker compose -f "$compose_file" -p "$compose_proj" config -q || die "compose syntax error"
    
    log_i "pulling images…"
    pull_from_compose
    docker pull "$alpine_img" >/dev/null || true
    
    [[ -f "$vol_file" ]] || die ".volumes not found: $vol_file"
    b64_syn="$(sed -n 's/^volume_synapse="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    b64_pg="$(sed -n 's/^volume_postgres="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    b64_tun="$(sed -n 's/^volume_tunnel="\([^"]*\)".*/\1/p' "$vol_file" || true)"
    [[ -n "$b64_syn" && -n "$b64_pg" && -n "$b64_tun" ]] || die "missing volume payloads in .volumes (require synapse, postgres, tunnel)"
    
    tmp_dir="$(mktemp -d -t matrix-restore-backup.XXXXXXXX)"
    printf '%s' "$b64_syn" | base64 -d > "${tmp_dir}/synapse.tar.xz"
    printf '%s' "$b64_pg" | base64 -d > "${tmp_dir}/postgres.tar.xz"
    printf '%s' "$b64_tun" | base64 -d > "${tmp_dir}/tunnel.tar.xz"
    
    log_i "removing project volumes…"
    docker volume rm -f "$vol_syn_name" "$vol_pg_name" "$vol_redis_name" "$vol_tun_name" >/dev/null 2>&1 || true
    
    log_i "recreating volumes…"
    docker volume create "$vol_syn_name" >/dev/null
    docker volume create "$vol_pg_name"  >/dev/null
    docker volume create "$vol_tun_name" >/dev/null
    
    log_i "restoring synapse volume…"
    restore_volume_from_tarxz "$vol_syn_name" "${tmp_dir}/synapse.tar.xz" "/data"
    
    log_i "restoring postgres volume…"
    restore_volume_from_tarxz "$vol_pg_name" "${tmp_dir}/postgres.tar.xz" "/var/lib/postgresql/data"
    
    log_i "restoring tunnel volume…"
    restore_volume_from_tarxz "$vol_tun_name" "${tmp_dir}/tunnel.tar.xz" "/ssh"
    
    log_i "building tunnel image (no cache)…"
    docker compose -f "$compose_file" -p "$compose_proj" build --pull --no-cache tunnel >/dev/null
    
    log_i "starting stack…"
    docker compose -f "$compose_file" -p "$compose_proj" up -d --force-recreate
    
    log_i "waiting for Postgres…"
    wait_health "$ctr_pg_name" 120 || die "postgres unhealthy after restore-backup"
    
    log_i "waiting for Synapse…"
    wait_health "$ctr_syn_name" 180 || die "synapse unhealthy after restore-backup"
    
    log_i "waiting for Tunnel…"
    wait_health "$ctr_tun_name" 120 || die "tunnel unhealthy after restore-backup"
    
    rm_if_unused_image "$alpine_img"
    docker image prune -f >/dev/null 2>&1 || true
    docker builder prune -f >/dev/null 2>&1 || true
    
    log_i "restore-backup complete"
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/restore.service
    [Unit]
    Description=Restore (runs a single script)
    Wants=network-online.target
    After=network-online.target
    
    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/restore
    RemainAfterExit=no
    
    [Install]
    WantedBy=multi-user.target
CONF

    systemctl daemon-reload
}
setup_deploy_service() {
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/deploy
    #!/bin/bash
    # process /tmp/deploy/*.tar.xz -> promote to release, rotate backup, trigger build
    set -Eeuo pipefail
    IFS=$'\n\t'
    umask 077
    
    inbox_dir="/tmp/deploy"
    release_dir="/opt/matrix/deploy/release"
    backup_dir="/opt/matrix/deploy/backup"
    
    log_i() { printf "\033[1;34m[info]\033[0m %s\n" "$*"; }
    log_e() { printf "\033[1;31m[err ]\033[0m %s\n" "$*" >&2; }
    die() { log_e "$*"; exit 1; }
    need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
    
    need_cmd find
    need_cmd xz
    need_cmd tar
    need_cmd grep
    need_cmd install
    need_cmd flock
    need_cmd systemctl
    need_cmd sha256sum
    need_cmd base64
    need_cmd od
    need_cmd wc
    
    install -d -m 1777 "$inbox_dir"
    install -d -m 0700 "$release_dir" "$backup_dir"
    
    exec 9>/run/matrix-deploy.lock
    if ! flock -n 9; then
        log_i "another deploy run is in progress, exiting"
        exit 0
    fi
    
    candidate="$(find "$inbox_dir" -maxdepth 1 -type f -name '*.tar.xz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1{print $2}')"
    [[ -n "$candidate" ]] || exit 0
    log_i "candidate: $candidate"
    
    # quick integrity checks
    if ! xz -t "$candidate" >/dev/null 2>&1; then
        log_e "xz test failed: $candidate"
        exit 1
    fi
    if ! tar -tJf "$candidate" data/docker-compose.yaml data/.volumes >/dev/null 2>&1; then
        log_e "archive missing required entries: data/docker-compose.yaml or data/.volumes"
        exit 1
    fi
    
    # extract .volumes into var
    vol_file="$(tar -xOJf "$candidate" data/.volumes 2>/dev/null || true)"
    [[ -n "$vol_file" ]] || die "cannot extract data/.volumes"
    
    get_vol_b64() {
        printf '%s\n' "$vol_file" | sed -n "s/^$1=\"\([^\"]*\)\".*/\1/p" | head -n1
    }
    
    b64_syn="$(get_vol_b64 volume_synapse)"
    b64_pg="$(get_vol_b64 volume_postgres)"
    b64_tun="$(get_vol_b64 volume_tunnel)"
    
    [[ -n "$b64_syn" ]] || die ".volumes missing volume_synapse"
    [[ -n "$b64_pg" ]] || die ".volumes missing volume_postgres"
    [[ -n "$b64_tun" ]] || die ".volumes missing volume_tunnel"
    
    check_b64_xz() {
        local name="$1" data="$2"
        local tmp
        tmp="$(mktemp -t "deploy.${name}.XXXXXXXX.xz")"
        if ! printf '%s' "$data" | base64 -d >"$tmp" 2>/dev/null; then
            log_e "$name: base64 decode failed"
            rm -f "$tmp"
            return 1
        fi
        local sig
        sig="$(od -An -N6 -tx1 "$tmp" | tr -d ' \n' | tr '[:upper:]' '[:lower:]' || true)"
        if [[ "$sig" != "fd377a585a00" ]]; then
            log_e "$name: decoded payload is not xz (magic=$sig)"
            rm -f "$tmp"
            return 1
        fi
        if ! xz -t "$tmp" >/dev/null 2>&1; then
            log_e "$name: xz test failed"
            rm -f "$tmp"
            return 1
        fi
        local b64len xzbytes
        b64len="$(printf '%s' "$data" | wc -c | tr -d ' ')"
        xzbytes="$(wc -c <"$tmp" | tr -d ' ')"
        log_i "$name: ok (base64_len=${b64len} xz_bytes=${xzbytes})"
        rm -f "$tmp"
        return 0
    }
    
    check_b64_xz "volume_synapse"  "$b64_syn"
    check_b64_xz "volume_postgres" "$b64_pg"
    check_b64_xz "volume_tunnel"   "$b64_tun"
    
    base="$(basename -- "$candidate")"
    rev="${base%.tar.xz}"
    new_sha="$(sha256sum "$candidate" | awk '{print $1}')"
    
    cur_path="$(ls -1t "$release_dir"/*.tar.xz 2>/dev/null | head -n1 || true)"
    cur_sha=""
    cur_rev=""
    if [[ -n "$cur_path" ]]; then
        cur_sha="$(sha256sum "$cur_path" | awk '{print $1}')"
        cur_rev="$(basename -- "$cur_path")"
        cur_rev="${cur_rev%.tar.xz}"
    fi
    
    if [[ -n "$cur_sha" && "$new_sha" == "$cur_sha" ]]; then
        log_i "already current (rev=$cur_rev, sha256 match); dropping $base"
        rm -f -- "$candidate"
        # unlock before exit
        flock -u 9 || true
        exit 0
    fi
    
    log_i "promoting to release (rev=$rev, new_sha=$new_sha cur_sha=${cur_sha:-none})"
    rm -f "$backup_dir"/*.tar.xz 2>/dev/null || true
    [[ -n "$cur_path" ]] && mv -f -- "$cur_path" "$backup_dir/"
    
    mv -f -- "$candidate" "$release_dir/$base"
    chown root:root "$release_dir/$base" 2>/dev/null || true
    printf '%s %s\n' "$rev" "$new_sha" > "$release_dir/.current"
    
    find "$inbox_dir" -maxdepth 1 -type f -name '*.tar.xz' -not -path "$release_dir/$base" -delete || true
    log_i "release updated: $base"
    
    # release lock before starting build
    flock -u 9 || true
    
    systemctl reset-failed build.service >/dev/null 2>&1 || true
    if ! systemctl start --no-block build.service; then
        log_e "failed to start build.service"
    fi
    
    exit 0
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/deploy.service
    [Unit]
    Description=Deploy (runs a single script)
    Wants=network-online.target
    After=network-online.target
    
    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/deploy
    RemainAfterExit=no
    
    [Install]
    WantedBy=multi-user.target
CONF

    systemctl daemon-reload
}
configure_systemd_networkd_static() {
    ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
    local host_net_ipv4_public_if_name="$(ip -4 route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $5}')"
    [ -n "${host_net_ipv4_public_if_name:-}" ] || host_net_ipv4_public_if_name="$(ip -o link | awk -F': ' '$2 ~ /^(eth|ens|enp)/{print $2; exit}')"
    local host_net_ipv4_uplink_default_addr="$(ip -4 route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $3}')"
    local host_net_ipv4_public_if_addr="$(LC_ALL=C ip -4 route get 255.255.255.255 2>/dev/null | grep -Po 'src\s+\K([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
    local host_net_ipv4_public_if_prefixlen="$(LC_ALL=C ip -4 -o addr show dev "$host_net_ipv4_public_if_name" 2>/dev/null | awk '$3=="inet"{for(i=1;i<=NF;i++){t=$i;if(t~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/){n=index(t,"/");print substr(t,n+1);exit}}}')"
    [ -n "${host_net_ipv4_public_if_name:-}" ] && [ -n "${host_net_ipv4_uplink_default_addr:-}" ] && [ -n "${host_net_ipv4_public_if_addr:-}" ] && [[ "${host_net_ipv4_public_if_prefixlen:-}" =~ ^[0-9]+$ ]] || exit 0
    local host_net_ipv4_public_if_cidr="${host_net_ipv4_public_if_addr}/${host_net_ipv4_public_if_prefixlen}"
    local host_net_ipv4_public_if_mask_u32="$(( (0xFFFFFFFF << (32 - host_net_ipv4_public_if_prefixlen)) & 0xFFFFFFFF ))"
    local host_net_ipv4_public_if_netmask="$(printf '%d.%d.%d.%d' $(((host_net_ipv4_public_if_mask_u32>>24)&255)) $(((host_net_ipv4_public_if_mask_u32>>16)&255)) $(((host_net_ipv4_public_if_mask_u32>>8)&255)) $((host_net_ipv4_public_if_mask_u32&255)))"
    local host_net_ipv4_public_if_addr_int="$(ip2int "$host_net_ipv4_public_if_addr")"
    local host_net_ipv4_public_if_netmask_int="$(ip2int "$host_net_ipv4_public_if_netmask")"
    local host_net_ipv4_uplink_default_addr_int="$(ip2int "$host_net_ipv4_uplink_default_addr")"
    local host_net_ipv4_public_if_network_int="$(( host_net_ipv4_public_if_addr_int & host_net_ipv4_public_if_netmask_int ))"
    local host_net_ipv4_uplink_default_network_int="$(( host_net_ipv4_uplink_default_addr_int & host_net_ipv4_public_if_netmask_int ))"
    local host_net_ipv4_uplink_default_onlink_bool=$([ "$host_net_ipv4_public_if_prefixlen" -eq 32 ] || [ "$host_net_ipv4_public_if_network_int" -ne "$host_net_ipv4_uplink_default_network_int" ] && echo yes || echo no)
    local host_net_ipv4_public_if_mac="$(cat /sys/class/net/"$host_net_ipv4_public_if_name"/address 2>/dev/null || true)"

    command -v networkctl >/dev/null 2>&1 || {
      install -d -m 0755 -o root -g root /etc/apt/apt.conf.d
      printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y --no-install-recommends systemd >/dev/null 2>&1 || true
    }

    install -d -m 0755 -o root -g root /etc/cloud/cloud.cfg.d
    printf "network: {config: disabled}\n" >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
    rm -f /etc/netplan/*.yaml 2>/dev/null || true
    install -d -m 0755 -o root -g root /etc/systemd/network

    if [ "$host_net_ipv4_uplink_default_onlink_bool" = "yes" ]; then
        cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/network/10-${host_net_ipv4_public_if_name}.network
        [Match]
        MACAddress=${host_net_ipv4_public_if_mac}

        [Network]
        Address=${host_net_ipv4_public_if_cidr}
        KeepConfiguration=static
        ConfigureWithoutCarrier=yes
        IgnoreCarrierLoss=yes
        IPv6AcceptRA=no

        [Route]
        Gateway=${host_net_ipv4_uplink_default_addr}
        GatewayOnLink=yes
CONF
    else
        cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/network/10-${host_net_ipv4_public_if_name}.network
        [Match]
        MACAddress=${host_net_ipv4_public_if_mac}

        [Network]
        Address=${host_net_ipv4_public_if_cidr}
        Gateway=${host_net_ipv4_uplink_default_addr}
        KeepConfiguration=static
        ConfigureWithoutCarrier=yes
        IgnoreCarrierLoss=yes
        IPv6AcceptRA=no
CONF
    fi

    ip -o -4 addr show dev "$host_net_ipv4_public_if_name" | grep -q -F "${host_net_ipv4_public_if_cidr}" || ip address add "$host_net_ipv4_public_if_cidr" dev "$host_net_ipv4_public_if_name" 2>/dev/null || true
    if [ "$host_net_ipv4_uplink_default_onlink_bool" = "yes" ]; then
        ip route replace "${host_net_ipv4_uplink_default_addr}/32" dev "$host_net_ipv4_public_if_name" 2>/dev/null || true
        ip route replace default via "$host_net_ipv4_uplink_default_addr" dev "$host_net_ipv4_public_if_name" onlink 2>/dev/null || true
    else
        ip route replace default via "$host_net_ipv4_uplink_default_addr" dev "$host_net_ipv4_public_if_name" 2>/dev/null || true
    fi

    install -d -m 0755 -o root -g root /etc/udev/rules.d
    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/udev/rules.d/99z-fq-qdisc.rules
    SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="$host_net_ipv4_public_if_mac", RUN+="/usr/sbin/tc qdisc replace dev %k root fq"
CONF

    udevadm control --reload
    systemctl daemon-reload
    systemctl enable --now systemd-networkd.service >/dev/null 2>&1 || true
    networkctl reload >/dev/null 2>&1 || true
    networkctl reconfigure "$host_net_ipv4_public_if_name" >/dev/null 2>&1 || true

    i=0; ok=0
    while [ $i -lt 10 ]; do 
        ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && { ok=1; break; }; i=$((i+1)); sleep 1
    done
    [ $ok -ne 1 ] && exit 1

    systemctl disable networking NetworkManager NetworkManager-dispatcher network-manager ifplugd >/dev/null 2>&1 || true
    systemctl mask networking NetworkManager NetworkManager-dispatcher network-manager ifplugd >/dev/null 2>&1 || true
    pkill -x dhclient >/dev/null 2>&1 || true
    pkill -x dhcpcd >/dev/null 2>&1 || true
    rm -f /etc/network/interfaces 2>/dev/null || true
    rm -rf /etc/network/interfaces.d /etc/network/if-pre-up.d /etc/network/if-up.d /etc/network/if-post-down.d /etc/network/if-down.d 2>/dev/null || true
    systemctl enable --now systemd-networkd-wait-online.service >/dev/null 2>&1 || true
    install -d -m 0755 -o root -g root /etc/systemd/system/systemd-networkd-wait-online.service.d
    cat <<CONF | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf
    [Service]
    ExecStart=
    ExecStart=/lib/systemd/systemd-networkd-wait-online --interface=${host_net_ipv4_public_if_name} --timeout=30
CONF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart systemd-networkd-wait-online.service >/dev/null 2>&1 || true
    apt-get -y purge ifupdown ifupdown2 netplan.io >/dev/null 2>&1
}
setup_unbound() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends ca-certificates unbound unbound-anchor dns-root-data >/dev/null 2>&1 || true

    install -d -m 0750 -o unbound -g unbound /var/lib/unbound
    unbound-anchor -v -a /var/lib/unbound/root.key || echo "unbound-anchor failed (will fallback)" >&2
    if [ ! -s /var/lib/unbound/root.key ]; then
        install -D -m 0644 -o unbound -g unbound /usr/share/dns/root.key /var/lib/unbound/root.key
    fi
    chown unbound:unbound /var/lib/unbound/root.key
    chmod 0644 /var/lib/unbound/root.key

    local mem_kib mem_bytes cg_limit mem_gib cpus
    local num_threads so_reuseport msg_cache rrset_cache infra_hosts
    mem_kib=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    mem_bytes=$(( mem_kib * 1024 ))

    if [ -r /sys/fs/cgroup/memory.max ]; then
        cg_limit=$(< /sys/fs/cgroup/memory.max)
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        cg_limit=$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)
    else
        cg_limit=""
    fi

    if [ -n "${cg_limit:-}" ] && [ "$cg_limit" != "max" ] && [ "$cg_limit" -gt 0 ] && [ "$cg_limit" -lt $((1<<60)) ] && [ "$cg_limit" -lt "$mem_bytes" ]; then
        mem_bytes="$cg_limit"
    fi

    mem_gib=$(( (mem_bytes + 1073741823) / 1073741824 ))
    (( mem_gib < 1 )) && mem_gib=1

    if command -v nproc >/dev/null 2>&1; then
        cpus=$(nproc)
    else
        cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    fi
    (( cpus < 1 )) && cpus=1

    num_threads=1
    msg_cache="16m"
    rrset_cache="32m"
    infra_hosts=10000

    if   (( mem_gib <= 1 )); then
        :
    elif (( mem_gib <= 2 )); then
        msg_cache="32m";  rrset_cache="64m";   infra_hosts=20000
    elif (( mem_gib <= 4 )); then
        (( num_threads = cpus >= 2 ? 2 : 1 ))
        msg_cache="64m";  rrset_cache="128m";  infra_hosts=40000
    elif (( mem_gib <= 8 )); then
        (( num_threads = cpus > 4 ? 4 : cpus )); (( num_threads < 2 )) && num_threads=2
        msg_cache="128m"; rrset_cache="256m";  infra_hosts=80000
    else
        (( num_threads = cpus > 8 ? 8 : cpus )); (( num_threads < 2 )) && num_threads=2
        msg_cache="256m"; rrset_cache="512m";  infra_hosts=160000
    fi

    so_reuseport=$([ "$num_threads" -gt 1 ] && echo yes || echo no)

    install -d -m 0755 -o root -g root /etc/unbound
    cat <<CONF | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/unbound/unbound.conf
    server:
        interface: 127.0.0.1
        port: 53
        access-control: 0.0.0.0/0 refuse
        access-control: 127.0.0.0/8 allow
        directory: "/etc/unbound"
        do-daemonize: no
        username: ""
        pidfile: ""
        identity: ""
        version: ""
        hide-identity: yes
        hide-version: yes
        qname-minimisation: yes
        qname-minimisation-strict: yes
        prefetch: yes
        prefetch-key: yes
        harden-glue: yes
        harden-short-bufsize: yes
        harden-algo-downgrade: yes
        harden-dnssec-stripped: yes
        harden-below-nxdomain: yes
        harden-referral-path: yes
        val-clean-additional: yes
        use-caps-for-id: yes
        deny-any: yes
        minimal-responses: yes
        aggressive-nsec: yes
        edns-buffer-size: 1232
        max-udp-size: 1232
        do-not-query-localhost: yes
        do-ip6: no
        do-tcp: yes
        tcp-upstream: yes
        use-syslog: no
        auto-trust-anchor-file: "/var/lib/unbound/root.key"
        tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
        module-config: "validator iterator"
        private-address: 10.0.0.0/8
        private-address: 172.16.0.0/12
        private-address: 192.168.0.0/16
        private-address: 169.254.0.0/16
        private-address: 100.64.0.0/10
        num-threads: ${num_threads}
        so-reuseport: ${so_reuseport}
        msg-cache-size: ${msg_cache}
        rrset-cache-size: ${rrset_cache}
        infra-cache-numhosts: ${infra_hosts}
        cache-min-ttl: 0
        cache-max-ttl: 21600
        cache-max-negative-ttl: 900
        serve-expired: no

    include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
CONF
    
    install -d -m 0755 -o root -g root /etc/unbound/unbound.conf.d
    rm -f /etc/unbound/unbound.conf.d/*
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/unbound/unbound.conf.d/10-forward.conf
    forward-zone:
        name: "."
        forward-tls-upstream: yes
        forward-addr: 1.1.1.1@853#cloudflare-dns.com
        forward-addr: 1.0.0.1@853#cloudflare-dns.com
        forward-addr: 94.140.14.140@853#unfiltered.adguard-dns.com
        forward-addr: 94.140.14.141@853#unfiltered.adguard-dns.com
CONF

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/unbound/unbound.conf.d/10-stats.conf
    server:
        extended-statistics: yes
        statistics-inhibit-zero: yes
CONF

    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/unbound/unbound.conf.d/10-remote-control.conf
    remote-control:
        control-enable: yes
        control-interface: "/run/unbound/unbound.ctl"
        control-use-cert: no
CONF

    install -d -m 0750 -o unbound -g unbound /var/lib/unbound/rpz
    rm -f /var/lib/unbound/rpz/*
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/unbound/unbound.conf.d/10-rpz.conf
    server:
        module-config: "respip validator iterator"

    rpz:
      name: "urlhaus"
      url: "https://urlhaus.abuse.ch/downloads/rpz/"
      zonefile: "/var/lib/unbound/rpz/urlhaus.rpz"
      rpz-action-override: nxdomain
      rpz-log: no
    
    rpz:
      name: "hagezi-doh"
      url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/doh.txt"
      zonefile: "/var/lib/unbound/rpz/hagezi-doh.rpz"
      rpz-action-override: nxdomain
      rpz-log: no
CONF

    install -d -m 0755 -o root -g root /etc/systemd/system/unbound.service.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/unbound.service.d/override.conf
    [Unit]
    After=network-online.target
    Wants=network-online.target
    RequiresMountsFor=/tmp

    [Service]
    ExecStart=
    ExecStartPre=
    ExecStopPost=
    User=unbound
    Group=unbound

    ExecStartPre=/usr/sbin/unbound-checkconf /etc/unbound/unbound.conf
    ExecStartPre=-/usr/sbin/unbound-anchor -a /var/lib/unbound/root.key
    ExecStart=/usr/sbin/unbound -d -c /etc/unbound/unbound.conf

    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelLogs=yes
    ProtectControlGroups=yes
    ProtectClock=yes
    ProtectHostname=yes
    LockPersonality=yes
    RestrictSUIDSGID=yes
    MemoryDenyWriteExecute=yes
    RestrictNamespaces=yes
    SystemCallFilter=@system-service
    ProcSubset=pid
    ProtectProc=invisible
    ProtectKernelModules=yes
    SystemCallArchitectures=native
    RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    ReadWritePaths=/run/unbound /var/lib/unbound
    RuntimeDirectory=unbound
    RuntimeDirectoryMode=0750
    StateDirectory=unbound
    StateDirectoryMode=0750
    Restart=on-failure
    RestartSec=2s
    UMask=0027
    LimitNOFILE=65536
    PrivateIPC=yes
    PrivateMounts=yes
    KeyringMode=private
    TasksMax=256
    SystemCallErrorNumber=EPERM
    TimeoutStopSec=10s
CONF

    install -d -m 0755 -o root -g root /etc/systemd/system/unbound-resolvconf.service.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/unbound-resolvconf.service.d/override.conf
    [Unit]
    ConditionFileIsExecutable=
    [Service]
    Type=oneshot
    ExecStart=
    ExecStart=/bin/true
    RemainAfterExit=yes
CONF

    install -d -m 0755 -o root -g root /etc/apparmor.d/local
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/apparmor.d/local/usr.sbin.unbound
    owner /run/unbound/** rw,
    capability chown,
    capability fowner,
CONF

    if systemctl is-active --quiet apparmor; then
        systemctl reload apparmor || aa-status >/dev/null 2>&1 || true
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart unbound-resolvconf.service >/dev/null 2>&1 || true
    systemctl enable --now unbound.service >/dev/null 2>&1 || true
    sleep 10
    systemctl restart unbound.service >/dev/null 2>&1 || true

    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/resolv.conf
    nameserver 127.0.0.1
    options edns0 trust-ad
CONF
    chattr +i /etc/resolv.conf 2>/dev/null || true

    systemctl mask systemd-resolved.service >/dev/null 2>&1 || true
    systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Use-Pty=0 purge resolvconf systemd-resolved >/dev/null 2>&1 || true
}
setup_ntpd_rs() {
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y ntpd-rs curl ca-certificates >/dev/null 2>&1 || true
    systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
    systemctl mask systemd-timesyncd.service 2>/dev/null || true
    
    install -d -m 0755 -o root -g root /usr/local/sbin
    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/secure-pretime.sh
    #!/bin/bash
    set -Eeuo pipefail
    last="/var/lib/secure-boot-time/last_epoch"
    floor_epoch=1735689600  # 2025-01-01T00:00:00Z
    now="$(date +%s 2>/dev/null || echo 0)"

    if [ -s "$last" ]; then
        tgt="$(tr -d '\n' <"$last" 2>/dev/null || echo 0)"
        if [ "$tgt" -gt "$now" ]; then
            date -u -s "@$tgt" >/dev/null
            exit 0
        fi
    fi

    if [ "$now" -lt "$floor_epoch" ]; then
        date -u -s "@$floor_epoch" >/dev/null
    fi
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/secure-pretime.service
    [Unit]
    Description=Set system clock from last_good_time before network
    DefaultDependencies=no
    Before=network-pre.target network.target network-online.target ntpd-rs.service
    After=local-fs.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/secure-pretime.sh
    StandardOutput=null
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
CONF

    install -d -m 0755 -o root -g root /etc/ntpd-rs
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/ntpd-rs/ntp.toml
    [observability]
    observation-path = "/var/run/ntpd-rs/observe"
    observation-permissions = 0o660

    [synchronization]
    minimum-agreeing-sources = 1
    startup-step-panic-threshold = { forward = "inf", backward = 86400 }

    [synchronization.algorithm]
    step-threshold = 5.0

    [[source]]
    mode = "nts"
    address = "time.cloudflare.com:4460"

    [[source]]
    mode = "nts"
    address = "nts.netnod.se:4460"
    
    [[source]]
    mode = "nts"
    address = "nts.time.nl:4460"
CONF

    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/tls-wait-time-sync.sh
    #!/bin/bash
    set -Eeuo pipefail

    threshold=5
    deadline=180

    SECONDS=0
    while (( SECONDS < deadline )); do
        epoch="$(curl -fs --tlsv1.3 --http2 --proto '=https' --max-time 5 --retry 2 --retry-all-errors -D - -o /dev/null --resolve one.one.one.one:443:1.1.1.1 https://one.one.one.one/ | tr -d '\r' | sed -n 's/^[Dd]ate:[[:space:]]*//p' | head -n1 | xargs -I{} date -u -d "{}" +%s 2>/dev/null || echo 0)"
        now="$(date +%s 2>/dev/null || echo 0)"
        if [ "$epoch" -gt 0 ] && [ "$now" -gt 0 ]; then
            diff=$(( now - epoch )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
            if [ "$diff" -le "$threshold" ]; then
                exit 0
            fi
        fi
        sleep 1
    done

    exit 1
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/tls-wait-time-sync.service
    [Unit]
    Description=Block time-sync.target until TLS time ok
    After=network-online.target ntpd-rs.service
    Wants=network-online.target time-sync.target
    Before=time-sync.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/tls-wait-time-sync.sh
    StandardOutput=null
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
CONF

    cat <<'CONF' | indent -4 | install -D -m 0755 -o root -g root /dev/stdin /usr/local/sbin/secure-pretime-update.sh
    #!/bin/bash
    set -Eeuo pipefail
    install -d -m 0700 -o root -g root /var/lib/secure-boot-time
    out="/var/lib/secure-boot-time/last_epoch"
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT

    date_line="$(curl -fs --tlsv1.3 --http2 --proto '=https' --max-time 5 --retry 2 --retry-all-errors -D - -o /dev/null --resolve one.one.one.one:443:1.1.1.1 https://one.one.one.one/ | tr -d '\r' | sed -n 's/^[Dd]ate:[[:space:]]*//p' | head -n1)"
    [ -n "$date_line" ] || exit 0

    epoch="$(date -u -d "$date_line" +%s 2>/dev/null || echo 0)"
    [ "$epoch" -ge 1704067200 ] || exit 0   # sanity floor (2024-01-01)

    umask 077
    printf '%s\n' "$epoch" >"$tmp"
    mv -f "$tmp" "$out"
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/secure-pretime-update.service
    [Unit]
    Description=Store last good time from TLS
    After=network-online.target ntpd-rs.service
    Wants=network-online.target

    [Service]
    Type=oneshot
    ExecStart=/usr/local/sbin/secure-pretime-update.sh
    StandardOutput=null
    StandardError=journal
CONF

    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/secure-pretime-update.timer
    [Unit]
    Description=Daily persist of last good time

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=24h
    Persistent=true

    [Install]
    WantedBy=timers.target
CONF

    install -d -m 0755 -o root -g root /etc/systemd/system/ntpd-rs.service.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system/ntpd-rs.service.d/override.conf
    [Service]
    Environment=RUST_LOG=error
    StandardOutput=null
    StandardError=journal
CONF

    systemctl daemon-reload
    systemctl enable --now secure-pretime.service
    systemctl enable --now ntpd-rs.service
    systemctl enable --now tls-wait-time-sync.service
    systemctl enable --now secure-pretime-update.timer
}
setup_matrix() {
    install -d -m 0750 -o root -g root /opt/matrix/deploy/{release,backup}
}
configure_change_hostname() {
    local random_hostname=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 19)
    echo "$random_hostname" > /etc/hostname
    hostname $random_hostname
    sed -i "s/127\.0\.1\.1\s.*/127.0.1.1\t${random_hostname}/g" /etc/hosts
}
configure_disable_ipv6() {
    if _is_ipv6_modular; then
        install -d -m 0755 -o root -g root /etc/modprobe.d
        cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/modprobe.d/99-ipv6.conf
        options ipv6 disable=1
        blacklist ipv6
CONF
    fi

    install -d -m 0755 -o root -g root /etc/default/grub.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/default/grub.d/99-disable-ipv6.cfg
    GRUB_CMDLINE_LINUX_DEFAULT="$(printf '%s' "$GRUB_CMDLINE_LINUX_DEFAULT" | sed -E 's/(^| )ipv6\.disable=1( |$)//g') ipv6.disable=1"
CONF
    command -v update-grub >/dev/null 2>&1 && update-grub >/dev/null 2>&1 || true
}
purge_exim4_full() {
    set -euo pipefail
    systemctl disable --now exim4.service >/dev/null 2>&1 || true
    systemctl mask exim4.service >/dev/null 2>&1 || true
    exim_pkgs="$(dpkg -l 'exim4*' 2>/dev/null | awk '/^(ii|rc)/{print $2}')"
    if [ -n "${exim_pkgs:-}" ]; then
        apt-get update >/dev/null 2>&1 || true
        apt-get purge -y $exim_pkgs >/dev/null 2>&1 || true
    fi
    rm -rf /etc/exim4 >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed   >/dev/null 2>&1 || true
}
logs_quiet_begin() {
    install -d -m 0755 -o root -g root /etc/systemd/journald.conf.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/journald.conf.d/99-investigation.conf
    [Journal]
    Storage=none
    ForwardToSyslog=no
    ForwardToConsole=no
    ForwardToWall=no
    SystemMaxUse=1M
    RuntimeMaxUse=1M
CONF
    systemctl daemon-reload
    systemctl restart systemd-journald

    install -d -m 0755 -o root -g root /etc/profile.d
    cat <<'CONF' | indent -4 | install -D -m 0644 -o root -g root /dev/stdin /etc/profile.d/00-nohistory.sh
    export HISTFILE=/dev/null
    export HISTSIZE=0
    export HISTFILESIZE=0
    if [ -n "${BASH_VERSION-}" ]; then
        set +o history 2>/dev/null || true
    fi
CONF

    install -D -m 0644 -o root -g root /dev/null /etc/environment
    grep -qE '^HISTFILE=' /etc/environment || printf 'HISTFILE=/dev/null\n' >> /etc/environment
    grep -qE '^HISTSIZE=' /etc/environment || printf 'HISTSIZE=0\n' >> /etc/environment
    grep -qE '^HISTFILESIZE=' /etc/environment || printf 'HISTFILESIZE=0\n' >> /etc/environment
    ln -sf /dev/null /root/.bash_history 2>/dev/null || true
    ln -sf /dev/null /etc/skel/.bash_history 2>/dev/null || true

    install -d -m 0755 -o root -g root /etc/systemd/coredump.conf.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/coredump.conf.d/50-no-core.conf
    [Coredump]
    Storage=none
    ProcessSizeMax=0
CONF

    install -d -m 0755 -o root -g root /etc/security/limits.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/security/limits.d/50-no-core.conf
    * hard core 0
    * soft core 0
CONF

    install -d -m 0755 -o root -g root /etc/systemd/system.conf.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/system.conf.d/50-core-off.conf
    [Manager]
    DefaultLimitCORE=0
CONF
}
logs_quiet_end() {
    dmesg -C 2>/dev/null || true
    find /var/log/journal -type f -name '*.journal*' -delete 2>/dev/null || true
    find /run/log/journal -type f -name '*.journal*' -delete 2>/dev/null || true
    systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
    systemd-tmpfiles --create --prefix /run/log/journal  2>/dev/null || true

    for f in /var/log/btmp /var/log/wtmp /run/utmp; do
        [ -e "$f" ] && truncate -s 0 "$f" || true
    done
    find /var/log -type f ! -name '*.journal*' -exec truncate -s 0 {} + 2>/dev/null || true
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    swapoff -a 2>/dev/null || true
    swapon -a 2>/dev/null || true
    : > /root/.bash_history 2>/dev/null || true
    history -cw 2>/dev/null || true

    install -d -m 0755 -o root -g root /etc/systemd/journald.conf.d
    cat <<'CONF' | indent 0 | install -D -m 0644 -o root -g root /dev/stdin /etc/systemd/journald.conf.d/99-investigation.conf
    [Journal]
    Storage=persistent
    Compress=yes
    Seal=yes
    SplitMode=uid
    MaxRetentionSec=7day
    MaxFileSec=1day
    RateLimitIntervalSec=30s
    RateLimitBurst=10000
    MaxLevelStore=notice
    ForwardToSyslog=no
    ForwardToKMsg=no
    ReadKMsg=no
CONF
    systemctl daemon-reload
    systemctl stop rsyslog syslog-ng 2>/dev/null || true
    systemctl disable rsyslog syslog-ng 2>/dev/null || true
    systemctl restart systemd-journald
}
EOS

cat <<EOS >> /tmp/install.sh

unset HISTFILE HISTSAVE HISTMOVE HISTZONE HISTORY HISTLOG USERHST REMOTEHOST REMOTEUSER
export HISTSIZE=0
echo 'set +o history' >> ~/.bashrc

host_ssh_port="$host_ssh_port"
host_user="$host_user"
host_user_password="$host_user_password"
host_user_group="$host_user_group"
host_user_pubkey_ed25519="$public_ed25519_key"
host_deploy_pubkey_ed25519="$public_deploy_ed25519_key"

logs_quiet_begin
configure_repo
install_base_packages
install_iptables
install_docker
install_gvisor
configure_timezone
configure_path
configure_locales
setup_user
setup_deploy_user
configure_root_access
configure_faillock_debian
configure_security_update
configure_apparmor
configure_seccomp
configure_sysctl
configure_rps_service
configure_openssh
configure_sshd_config_guard
configure_os_updater
setup_wipe_service
setup_build_service
setup_restore_service
setup_deploy_service
setup_matrix_updater_service
configure_systemd_networkd_static
configure_disable_ipv6
setup_ntpd_rs
setup_unbound
setup_matrix
configure_iptables
configure_change_hostname
{ command -v exim4 >/dev/null 2>&1 || command -v exim >/dev/null 2>&1; } && purge_exim4_full
logs_quiet_end
reboot
EOS
}
check_vps_login() {
    clear; printf '\e[3J'
    test_login() {
        local vps_address=$1
        local vps_password=$2
        sshpass -p "${vps_password}" ssh \
            -o LogLevel=error \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ProxyCommand="socat -T 60 - SOCKS4A:${int_network_container_haproxy_ipv4}:%h:%p,socksport=9095" \
            root@${vps_address} 'exit' 2>/dev/null && return 0 || return 1
    }
    for i in {1..3}; do
        tor_newnym
        clear; printf '\e[3J'
        echo "Checking VPS before install: " >&2
        printf "%-22s %s" "Enter VPS ip address: " >&2
        read -r vps_address
        printf "%-22s %s" "Enter VPS password: " >&2
        read -rs vps_password
        printf "\n"
        test_login "$vps_address" "$vps_password" && {
            clear; printf '\e[3J'
            echo "VPS Login: Done." >&2
            sleep 1.5
            break
        } || printf "Incorrect ip address or password. Try again.\n" >&2
        [ $i -eq 3 ] && { printf "The maximum number of attempts has been reached.\nPlease try again later\n" >&2; exit 1; }
   done
}
install() {
    tor_newnym
    clear; printf '\e[3J'
    sshpass -p "${vps_password}" \
      ssh \
        -o LogLevel=error \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ProxyCommand="socat -T 60 - SOCKS4A:${int_network_container_haproxy_ipv4}:%h:%p,socksport=9095" \
        "root@${vps_address}" \
        'cat > /tmp/install.sh; sleep 4; nohup bash /tmp/install.sh >/dev/null 2>&1 & echo $! > /tmp/install.pid; sleep 4; ps -p $(cat /tmp/install.pid) >/dev/null' \
      < "/tmp/install.sh" \
    && { echo "Successful" || true; sleep 1.5; } || { echo "Fault"; return 1; }
}

set -x
clear_screen
echo "Check tor connection..."
sleep 10
check_vps_login
clear_screen
echo "Installing..."
declare -a generated_ports=()
host_ssh_port="$(generate_port 17000 63000)" || exit 1
host_user="$(generate_username)" || exit 1
host_user_password="$(generate_password)" || exit 1
host_user_group="$(generate_user_group)" || exit 1
read -r private_ed25519_key public_ed25519_key < <(generate_ssh_keys) || exit 1
read -r private_deploy_ed25519_key public_deploy_ed25519_key < <(generate_ssh_keys) || exit 1
configure_server_installer
install
set +x
clear_screen
print_tokens
SH

RUN chown -R user:user /home/user && \
    chmod +x /home/user/deploy

USER user
WORKDIR /home/user
CMD ["sleep","infinity"]
EOF
}
wait_health() {
    local name="$1" timeout="${2:-180}" id hs run i
    for ((i=0; i<timeout; i++)); do
        id="$(${SUDO:-} docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
        if [[ -n "$id" ]]; then
            hs="$(${SUDO:-} docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{""}}{{end}}' "$id" 2>/dev/null || true)"
            run="$(${SUDO:-} docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)"
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
    id="$(${SUDO:-} docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
    [[ -n "$id" ]] || return 0

    ${SUDO:-} docker inspect -f '{{range .State.Health.Log}}{{printf "[%s] code=%d %s\n" .Start .ExitCode .Output}}{{end}}' "$id" 1>&2 || true
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
sudo_keepalive_start 90
trap 'cleanup_all; exit 130' INT
trap 'cleanup_all' EXIT TERM HUP QUIT
check_pkg
preclean_patterns
tor_ctrl_pass="$(LC_ALL=C tr -dc 'A-Za-z0-9!?+=_' </dev/urandom | head -c 32 || true)"
tor_ctrl_hash="$(
    ${SUDO} docker run --rm debian:trixie-slim bash -ceu '
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
${SUDO} docker exec $tty_flag deploy /bin/bash -lc 'exec ./deploy'
