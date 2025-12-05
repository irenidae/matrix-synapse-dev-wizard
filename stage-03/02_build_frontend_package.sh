#!/bin/bash
set -Eeuo pipefail

# ───────────── helpers ─────────────
info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[ERR]\033[0m %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }
clear_scr() { clear 2>/dev/null || true; printf '\e[3J' 2>/dev/null || true; }

: "${STRICT_CLEANUP:=0}"
: "${PURGE_IMAGES:=1}"
: "${KEEP_ON_FAIL:=0}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    export LC_ALL=C
    export LANG=C
    export LC_CTYPE=C
fi

if xargs -r </dev/null echo >/dev/null 2>&1; then
    xargs_r='-r'
else
    xargs_r=''
fi
export xargs_r

SUDO=""

# ───────────── docker / sudo detection ─────────────
if [[ "$OSTYPE" == "darwin"* ]]; then
    info "macOS detected."

    if ! command -v docker >/dev/null 2>&1; then
        err "Docker is not installed."
        err "Install Docker Desktop, launch it, then re-run this script."
        die "Docker not available"
    fi

    if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
        sock="${DOCKER_HOST#unix://}"
        if [[ ! -S "$sock" ]]; then
            err "DOCKER_HOST points to '$sock', but that socket does not exist."
            err "Start Docker Desktop, or run:  unset DOCKER_HOST ; docker context use default"
            die "Invalid DOCKER_HOST"
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        err "Docker is installed but not running."
        err "Open Docker.app and wait until it finishes starting, then re-run this script."
        die "Docker daemon not running"
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
                    if ! sudo -v; then
                        die "sudo authentication failed."
                    fi
                    SUDO="sudo"
                else
                    err "docker requires sudo but no TTY is available to prompt for password."
                    err "add your user to the docker group or enable passwordless sudo for docker."
                    die "cannot use docker"
                fi
            fi
        else
            die "docker is not accessible and sudo is not installed."
        fi
    fi
fi

export SUDO

# ───────────── tmp tracking ─────────────
compose_up_flag=0
keep_on_fail="${KEEP_ON_FAIL:-0}"
declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image(){ _tmp_images+=("$1"); }

tmp_folder="$(mktemp -d -t frontend-session.XXXXXXXX)"
append_tmp_dir "$tmp_folder"
runtime_dir="${tmp_folder}/runtime"
mkdir -p "$runtime_dir"

make_tmp_dir() {
    local d
    d="$(mktemp -d "${tmp_folder}/d.XXXXXXXX")"
    append_tmp_dir "$d"
    printf '%s\n' "$d"
}
make_tmp_file() {
    local f
    f="$(mktemp "${tmp_folder}/f.XXXXXXXX")"
    append_tmp_file "$f"
    printf '%s\n' "$f"
}
# ───────────── sudo keepalive ─────────────
sudo_keepalive_start() {
    local max_minutes="${1:-60}"

    if [[ "${SUDO:-}" != "sudo" ]]; then
        return 0
    fi

    sudo -v || exit 1

    (
        local end
        end=$((SECONDS + max_minutes*60))
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
# ───────────── cleanup helpers ─────────────
prune_build_caches() {
    ${SUDO:-} docker builder prune -af >/dev/null 2>&1 || true

    if ${SUDO:-} docker buildx ls >/dev/null 2>&1; then
        if ${SUDO:-} docker buildx ls --format '{{.Name}}' >/dev/null 2>&1; then
            ${SUDO:-} docker buildx ls --format '{{.Name}}' \
                | while IFS= read -r bname; do
                      [[ -z "$bname" ]] && continue
                      bname="${bname%\*}"
                      ${SUDO:-} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
                  done
        else
            ${SUDO:-} docker buildx ls | awk 'NR>1{print $1}' \
                | while IFS= read -r bname; do
                      [[ -z "$bname" ]] && continue
                      bname="${bname%\*}"
                      ${SUDO:-} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
                  done
        fi
    fi
}
purge_runtime_images() {
    ${SUDO:-} docker images -q --filter "reference=deploy-token-prompter:*" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    ${SUDO:-} docker images -q --filter "reference=alpine:latest" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    ${SUDO:-} docker images -q --filter "reference=debian:trixie-slim" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    ${SUDO:-} docker images -q -f dangling=true | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
}
cleanup_images() {
    prune_build_caches

    if [[ "${STRICT_CLEANUP:-0}" == "1" ]]; then
        ${SUDO:-} docker system prune -af --volumes >/dev/null 2>&1 || true
    fi

    if [[ "${PURGE_IMAGES:-1}" == "1" ]]; then
        purge_runtime_images
    fi
}
cleanup_files() {
    local f d

    if [[ ${_tmp_files+x} ]]; then
        for f in "${_tmp_files[@]}"; do
            [[ -n "$f" ]] && rm -f -- "$f" >/dev/null 2>&1 || true
        done
    fi

    if [[ ${_tmp_dirs+x} ]]; then
        for d in "${_tmp_dirs[@]}"; do
            [[ -n "$d" ]] && rm -rf -- "$d" >/dev/null 2>&1 || true
        done
    fi

    if [[ -n "${tmp_folder:-}" && -d "${tmp_folder:-}" ]]; then
        rm -rf -- "${tmp_folder}" 2>/dev/null || true
    fi
}
preflight_cleanup() {
    info "Pre-flight cleanup (frontend containers/volumes/networks)"
    ${SUDO:-} docker ps -aq -f "name=^frontend_(nginx|tunnel)$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^frontend_(nginx_config|acme_state|tunnel)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^frontend_(internal|external)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    prune_build_caches
}
final_cleanup() {
    info "Final cleanup (frontend containers/volumes/networks)"
    ${SUDO:-} docker ps -aq -f "name=^frontend_(nginx|tunnel)$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^frontend_(nginx_config|acme_state|tunnel)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^frontend_(internal|external)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
}
cleanup_all() {
    set +e
    set +u

    if [[ "${KEEP_ON_FAIL:-0}" = "1" ]]; then
        info "KEEP_ON_FAIL=1 -> skip cleanup for debugging"
        sudo_keepalive_stop
        set -e
        set -u
        return 0
    fi

    final_cleanup
    cleanup_files
    cleanup_images
    sudo_keepalive_stop

    set -e
    set -u
}

sudo_keepalive_start 90
trap 'cleanup_all; exit 130' INT TERM HUP
trap 'cleanup_all' EXIT

# ───────────── docker presence / install ─────────────
check_pkg() {
    local os=""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        info "Docker on macOS is ready."
        return 0
    fi

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
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
                err "unsupported distro '$os' – install docker manually."
                return 1
                ;;
        esac
    else
        info "docker is present."
    fi

    if command -v systemctl >/dev/null 2>&1 && \
       systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service'; then
        sudo systemctl enable --now docker 2>/dev/null || true
    fi
}

# ───────────── prompt: domain + archive URL ─────────────
prompt_domain_and_archive_url() {
    get_domain_name() {
        clear_scr
        while true; do
            printf "Enter the domain name (e.g. example.com): " >&2
            IFS= read -r domain_name

            if [[ -z "$domain_name" ]]; then
                echo "Domain name cannot be empty." >&2
                continue
            fi

            printf "You entered domain '%s'. Confirm? (y/n/cancel): " "$domain_name" >&2
            IFS= read -r c
            case "$c" in
                y|Y|yes|Yes) break ;;
                n|N|no|No)
                    echo "Please enter the domain again." >&2
                    ;;
                cancel|Cancel)
                    echo "Operation canceled." >&2
                    exit 1
                    ;;
                *)
                    echo "Please type 'y', 'n', or 'cancel'." >&2
                    ;;
            esac
        done
    }
    get_archive_url() {
        clear_scr
        while true; do
            printf "Enter the site archive URL (e.g. https://example.com/site.tar.gz): " >&2
            IFS= read -r archive_url

            if [[ -z "$archive_url" ]]; then
                echo "Archive URL cannot be empty." >&2
                continue
            fi

            if [[ ! "$archive_url" =~ ^https?:// ]]; then
                echo "This does not look like a HTTP/HTTPS URL." >&2
                printf "Use '%s' anyway? (y/n/cancel): " "$archive_url" >&2
                IFS= read -r c
                case "$c" in
                    y|Y|yes|Yes) break ;;
                    n|N|no|No)
                        echo "Please enter the URL again." >&2
                        continue
                        ;;
                    cancel|Cancel)
                        echo "Operation canceled." >&2
                        exit 1
                        ;;
                    *)
                        echo "Please type 'y', 'n', or 'cancel'." >&2
                        continue
                        ;;
                esac
            else
                printf "You entered URL '%s'. Confirm? (y/n/cancel): " "$archive_url" >&2
                IFS= read -r c
                case "$c" in
                    y|Y|yes|Yes) break ;;
                    n|N|no|No)
                        echo "Please enter the URL again." >&2
                        continue
                        ;;
                    cancel|Cancel)
                        echo "Operation canceled." >&2
                        exit 1
                        ;;
                    *)
                        echo "Please type 'y', 'n', or 'cancel'." >&2
                        continue
                        ;;
                esac
            fi
        done
    }

    get_domain_name
    get_archive_url
}

# ───────────── prompt: Deploy Token (SSH tunnel, always used) ─────────────
prompt_deploy_token() {
    local image out cname="deploy_tmp_prompt_$$"
    image="deploy-token-prompter:alpine-$$_$(date +%s)"
    append_tmp_image "$image"

    cat <<'dockerfile' | ${SUDO:-} docker build -t "${image}" - >/dev/null
FROM alpine:latest
RUN apk add --no-cache bash xz coreutils gnupg pinentry-tty

RUN cat <<'SH' > /usr/local/bin/run.sh
#!/bin/bash
set -Eeuo pipefail

trap 'exit 130' INT

clear_screen() {
    clear 2>/dev/null || true
    printf '\e[3J' 2>/dev/null || true
}

prompt_tokens() {
    local attempts=0 s pass tail
    local hdr="jA0ECQMK"
    local k v line

    while (( attempts < 3 )); do
        printf "Enter Deploy Token [Stage 1]: " >&2
        IFS= read -r s || return 1

        s="${s%\"}"; s="${s#\"}"
        s="${s%\'}"; s="${s#\'}"
        s="$(printf '%s' "$s" | tr -d '\r\n \t')"

        local s1_bin s1_txt
        s1_bin="$(mktemp)"
        s1_txt="$(mktemp)"

        if (( ${#s} > 45 )) && [[ "${s:0:45}" =~ ^[A-Za-z0-9]{45}$ ]]; then
            pass="${s:0:45}"
            tail="${s:45}"
            if ! printf '%s' "${hdr}${tail}" | base64 -d 2>/dev/null | \
                   gpg --batch --yes --no-tty --quiet \
                       --pinentry-mode loopback \
                       --passphrase "$pass" \
                       --decrypt 2>/dev/null >"$s1_bin"; then
                clear_screen
                echo "decrypt failed" >&2
                attempts=$((attempts+1))
                rm -f "$s1_bin" "$s1_txt" 2>/dev/null || true
                continue
            fi
        else
            if ! printf '%s' "$s" | base64 -d >"$s1_bin" 2>/dev/null; then
                clear_screen
                echo "bad input" >&2
                attempts=$((attempts+1))
                rm -f "$s1_bin" "$s1_txt" 2>/dev/null || true
                continue
            fi
        fi

        if xz -t "$s1_bin" >/dev/null 2>&1; then
            if ! xz -dc <"$s1_bin" >"$s1_txt" 2>/dev/null; then
                clear_screen
                echo "xz decompress failed" >&2
                attempts=$((attempts+1))
                rm -f "$s1_bin" "$s1_txt" 2>/dev/null || true
                continue
            fi
        else
            cat <"$s1_bin" >"$s1_txt"
        fi

        local text_raw text
        text_raw="$(cat "$s1_txt")"
        text="$(printf '%b' "$text_raw")"

        rm -f "$s1_bin" "$s1_txt" 2>/dev/null || true

        unset ssh_raw ssh_user ssh_port srv_ip

        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            k="${line%%=*}"
            v="${line#*=}"
            v="${v%$'\r'}"
            v="${v%\"}"; v="${v#\"}"
            v="${v%\'}"; v="${v#\'}"
            case "$k" in
                ssh_raw)  ssh_raw="$v" ;;
                ssh_user) ssh_user="$v" ;;
                ssh_port) ssh_port="$v" ;;
                srv_ip)   srv_ip="$v" ;;
            esac
        done <<< "$text"

        local ssh_key tmp
        ssh_key="$(mktemp)"
        tmp="$(mktemp)"

        if printf '%s' "${ssh_raw:-}" | tr -d '\r\n \t' | base64 -d >"$tmp" 2>/dev/null; then
            if xz -t "$tmp" >/dev/null 2>&1; then
                if ! xz -dc <"$tmp" >"$ssh_key" 2>/dev/null; then
                    clear_screen
                    echo "ssh_raw decompress failed" >&2
                    attempts=$((attempts+1))
                    rm -f "$tmp" "$ssh_key" 2>/dev/null || true
                    continue
                fi
            else
                cp "$tmp" "$ssh_key"
            fi
        else
            printf '%s' "${ssh_raw:-}" >"$ssh_key"
        fi

        chmod 600 "$ssh_key" 2>/dev/null || true

        if ! grep -q "BEGIN OPENSSH PRIVATE KEY" "$ssh_key" 2>/dev/null; then
            clear_screen
            echo "final payload is not an OpenSSH private key" >&2
            attempts=$((attempts+1))
            rm -f "$tmp" "$ssh_key" 2>/dev/null || true
            continue
        fi

        if [[ ! "${ssh_port:-}" =~ ^[0-9]{1,5}$ || "${ssh_port:-0}" -lt 1 || "${ssh_port:-0}" -gt 65535 ]]; then
            clear_screen
            echo "bad ssh_port" >&2
            attempts=$((attempts+1))
            rm -f "$tmp" "$ssh_key" 2>/dev/null || true
            continue
        fi

        if [[ -z "${ssh_user:-}" || -z "${srv_ip:-}" ]]; then
            clear_screen
            echo "missing ssh_user/srv_ip" >&2
            attempts=$((attempts+1))
            rm -f "$tmp" "$ssh_key" 2>/dev/null || true
            continue
        fi

        rm -f "$tmp" "$ssh_key" 2>/dev/null || true
        clear_screen
        return 0
    done

    echo "too many attempts" >&2
    return 1
}

main_prompter() {
    exec 3>&1
    exec 1>&2

    while true; do
        clear_screen
        if ! prompt_tokens; then
            echo "bad token, retrying..." >&2
            continue
        fi
        clear_screen
        printf 'ssh_raw=%q\n' "${ssh_raw:-}" >&3
        printf 'ssh_user=%q\n' "${ssh_user:-}" >&3
        printf 'ssh_port=%q\n' "${ssh_port:-}" >&3
        printf 'srv_ip=%q\n' "${srv_ip:-}" >&3
        return 0
    done
}

main_prompter
SH

RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
dockerfile

    local -a tty_flags
    if [[ -t 0 && -t 1 ]]; then
        tty_flags=(-it)
    else
        tty_flags=(-i)
    fi

    trap '${SUDO:-} docker rm -f "'"$cname"'" >/dev/null 2>&1 || true' INT TERM HUP
    out="$(${SUDO:-} docker run --rm --name "$cname" "${tty_flags[@]}" "${image}")"
    trap - INT TERM HUP

    printf '%s\n' "$out"

    ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
}

# ───────────── create volumes (always includes tunnel) ─────────────
create_volumes() {
    info "Creating frontend volumes"
    ${SUDO:-} docker volume create frontend_nginx_config >/dev/null 2>&1
    ${SUDO:-} docker volume create frontend_tunnel >/dev/null 2>&1
}

# ───────────── seed tunnel volume ─────────────
seed_tunnel_volume() {
    info "Seeding tunnel volume"
    local t
    t="$(mktemp -d "${tmp_folder}/tunnelseed.XXXXXXXX")"
    append_tmp_dir "$t"
    install -d -m 0700 "$t"
    printf '%s' "$ssh_raw" > "$t/ssh_raw"

    cat > "$t/config" <<EOF
Host proxy
    Ciphers aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com
    KexAlgorithms sntrup761x25519-sha512@openssh.com
    HostKeyAlgorithms ssh-ed25519
    ChallengeResponseAuthentication no
    VersionAddendum none
    HostName ${srv_ip}
    Port ${ssh_port}
    User ${ssh_user}
    IdentityFile /ssh/id_ed25519
    CheckHostIP no
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ExitOnForwardFailure yes
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ControlMaster auto
    ControlPersist yes
    ControlPath /tmp/ssh_mux
EOF

    ${SUDO:-} docker run --rm -v frontend_tunnel:/ssh -v "$t":/src:ro \
        alpine:latest sh -eu -c '
            apk add --no-cache xz coreutils grep >/dev/null 2>&1 || true
            umask 077
            mkdir -p /ssh
            tr -d " \r\n\t" </src/ssh_raw | base64 -d | xz -dc > /ssh/id_ed25519

            grep -q "BEGIN OPENSSH PRIVATE KEY" /ssh/id_ed25519 || {
                echo "seed: invalid key payload" >&2
                exit 1
            }

            cp /src/config /ssh/config
            chown -R 1000:1000 /ssh
            chmod 600 /ssh/id_ed25519 /ssh/config
        '

    shred -u "$t/ssh_raw" 2>/dev/null || rm -f "$t/ssh_raw"
    rm -rf "$t"
    unset ssh_raw ssh_user ssh_port srv_ip
    info "Tunnel volume seeded"
}

# ───────────── seed nginx config + site ─────────────
seed_nginx_frontend() {
    info "Seeding nginx config and static site"
    local tmp_root src_cfg src_html
    tmp_root="$(mktemp -d "${tmp_folder}/nginxseed.XXXXXXXX")"
    append_tmp_dir "$tmp_root"
    src_cfg="${tmp_root}/src_nginx_config"
    mkdir -p "${src_cfg}/conf.d"

    cat > "${src_cfg}/nginx.conf" <<NGINX
load_module /usr/lib/nginx/modules/ngx_http_acme_module.so;

events {
    worker_connections 2048;
    use epoll;
}

http {
    sendfile on;
    keepalive_timeout 65;
    reset_timedout_connection on;
    send_timeout 3600;
    tcp_nopush on;
    tcp_nodelay on;
    open_file_cache max=500 inactive=10m;
    open_file_cache_errors on;
    access_log off;
    error_log /dev/stderr crit;
    resolver 127.0.0.11 valid=30s ipv6=off;
    resolver_timeout 5s;
    charset utf-8;
    etag off;
    types_hash_max_size 2048;
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    include /etc/nginx/conf.d/*.conf;

    gzip on;
    gzip_vary on;
    gzip_comp_level 2;
    gzip_types text/plain application/json application/javascript text/css image/x-icon font/ttf image/gif;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options SAMEORIGIN;
    add_header Content-Security-Policy "frame-ancestors 'self'";
    add_header Permissions-Policy interest-cohort=() always;

    map \$http_user_agent \$allowed_user_agent {
        default 0;
        "~^Element(?: [^/]+)*/.* \(iPhone.*; iOS .*; Scale/.*\)$" 1;
        "~^Mozilla/.* \(X11; Linux x86_64\) AppleWebKit/.* \(KHTML, like Gecko\) Element/.* Chrome/.* Electron/.* Safari/.*$" 1;
    }
}
NGINX

    cat > "${src_cfg}/conf.d/00-acme.conf" <<'NGINX'
acme_issuer letsencrypt {
    uri https://acme-v02.api.letsencrypt.org/directory;
    state_path /var/cache/nginx/acme/state;
    accept_terms_of_service;
    account_key ecdsa:384;
    challenge http-01;
}
acme_shared_zone zone=ngx_acme_shared:1M;
NGINX

    cat > "${src_cfg}/conf.d/site.conf" <<NGINX
server {
    listen 80;
    server_name ${domain_name};
    location /.well-known/acme-challenge/ { }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl;
    server_name ${domain_name};
    http2 on;

    acme_certificate letsencrypt;
    ssl_certificate \$acme_certificate;
    ssl_certificate_key \$acme_certificate_key;
    ssl_certificate_cache max=2;

    ssl_dhparam /etc/nginx/dhparam.pem;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve secp384r1;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    location ~ ^(/_matrix|/_synapse/client) {
        if (\$allowed_user_agent = 0) {
            return 404;
        }
        proxy_pass http://${docker_internal_tunnel_ipv4}:8008;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        client_body_buffer_size 25M;
        client_max_body_size 50M;
        proxy_max_temp_file_size 0;
    }

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
    }
}
NGINX

    cat > "${src_cfg}/mime.types" <<'NGX_TYPES'
types {
    text/html                    html htm shtml;
    text/css                     css;
    text/xml                     xml;
    image/gif                    gif;
    image/jpeg                   jpeg jpg;
    application/javascript       js;
    application/json             json;
    application/font-woff        woff;
    application/font-woff2       woff2;
    application/octet-stream     bin exe dll;
    video/mp4                    mp4;
    image/png                    png;
    image/svg+xml                svg svgz;
}
NGX_TYPES

    info "Generating dhparam.pem and copying config into frontend_nginx_config (single alpine run)..."
    ${SUDO:-} docker run --rm \
        -v frontend_nginx_config:/etc_nginx \
        -v "${src_cfg}":/src \
        alpine:latest sh -c '
            set -e
            apk add --no-cache openssl >/dev/null 2>&1
            openssl dhparam -out /src/dhparam.pem 2048
            cd /src
            cp -a . /etc_nginx/
        '

    info "Nginx config seeding done"
}

# ───────────── packaging ─────────────
final_slug="$( (command -v uuidgen >/dev/null 2>&1 && uuidgen || cat /proc/sys/kernel/random/uuid) | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]' )"
final_out_dir="${FINAL_TAR_DIR:-$HOME/Downloads/website}"
final_tar_path="${FINAL_TAR:-${final_out_dir}/${final_slug}.tar.xz}"

make_package() {
    local pkg_root tmp outdir
    pkg_root="$(mktemp -d "${tmp_folder}/frontend-pkg.XXXXXXXX")"
    append_tmp_dir "$pkg_root"
    tmp="$(mktemp -d "${tmp_folder}/frontend-vols.XXXXXXXX")"
    append_tmp_dir "$tmp"
    outdir="${pkg_root}/data"
    mkdir -p "$outdir"

    info "Packing docker volumes into tar.xz"

    ${SUDO:-} docker run --rm \
        --mount source=frontend_nginx_config,target=/cfg \
        -v "$tmp":/out alpine:latest sh -c \
        "apk add --no-cache xz >/dev/null 2>&1 && tar -cJf /out/nginx_config.tar.xz -C /cfg ."

    ${SUDO:-} docker run --rm \
        --mount source=frontend_tunnel,target=/ssh \
        -v "$tmp":/out alpine:latest sh -c \
        "apk add --no-cache xz >/dev/null 2>&1 && tar -cJf /out/tunnel.tar.xz -C /ssh ."

    b64_oneline() {
        local f="$1"
        if command -v openssl >/dev/null 2>&1; then
            openssl base64 -A -in "$f"
        else
            base64 "$f" | tr -d '\n'
        fi
    }

    {
        printf 'volume_frontend_nginx_config="'; b64_oneline "$tmp/nginx_config.tar.xz"; printf '"\n'
        printf 'volume_frontend_tunnel="'; b64_oneline "$tmp/tunnel.tar.xz"; printf '"\n'
    } > "$outdir/.volumes"

    chmod 600 "$outdir/.volumes"

    cat > "$outdir/.env" <<EOF
docker_internal_subnet_ipv4="${docker_internal_subnet_ipv4}"
docker_external_subnet_ipv4="${docker_external_subnet_ipv4}"
docker_internal_gw_ipv4="${docker_internal_gw_ipv4}"
docker_internal_nginx_ipv4="${docker_internal_nginx_ipv4}"
docker_internal_tunnel_ipv4="${docker_internal_tunnel_ipv4}"
docker_external_gw_ipv4="${docker_external_gw_ipv4}"
docker_external_nginx_ipv4="${docker_external_nginx_ipv4}"
docker_external_tunnel_ipv4="${docker_external_tunnel_ipv4}"
EOF

    cat > "$outdir/.url" <<EOF
$archive_url
EOF

    mkdir -p "$outdir/nginx"
    cat > "$outdir/nginx/Dockerfile" <<'EOF'
FROM nginx:trixie AS fetch
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu && \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg2 && \
    install -d -m 0755 /etc/apt/keyrings && \
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /etc/apt/keyrings/nginx.gpg && \
    . /etc/os-release; echo "deb [signed-by=/etc/apt/keyrings/nginx.gpg] http://nginx.org/packages/mainline/debian ${VERSION_CODENAME} nginx" > /etc/apt/sources.list.d/nginx.list && \
    apt-get update && apt-get install -y --no-install-recommends nginx-module-acme && \
    cp /usr/lib/nginx/modules/ngx_http_acme_module.so /tmp/ngx_http_acme_module.so

FROM nginx:trixie

COPY --from=fetch /tmp/ngx_http_acme_module.so /usr/lib/nginx/modules/ngx_http_acme_module.so

RUN mkdir -p /var/cache/nginx/acme/state && \
    chown -R 101:101 /var/cache/nginx/acme && \
    chmod 700 /var/cache/nginx/acme/state
EOF

    mkdir -p "$outdir/tunnel"
    cat > "$outdir/tunnel/Dockerfile" <<'EOF'
FROM debian:trixie-slim

ARG docker_internal_tunnel_ipv4
ENV docker_internal_tunnel_ipv4="${docker_internal_tunnel_ipv4}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates apt-transport-https && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt upgrade -y && \
    apt-get install -y --no-install-recommends openssh-client curl bash tzdata && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get purge -y apt-transport-https && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /usr/sbin/nologin tunnel || true
RUN cat <<'EOS' > /usr/local/bin/docker-entrypoint.sh
#!/bin/bash
set -Eeuo pipefail

local_bind_host="${docker_internal_tunnel_ipv4}"
local_bind_port="8008"
remote_target="127.0.0.1:8008"
api_url="http://${local_bind_host}:${local_bind_port}/health"
backoff=5
backoff_max=30
max_fail=3
fail_count=0

trap 'exit 0' INT TERM

ensure_tunnel() {
    if ssh -q -F /ssh/config -o BatchMode=yes -o ConnectTimeout=5 -O check proxy 2>/dev/null; then
        return 0
    fi
    ssh -F /ssh/config -MNf -o BatchMode=yes -o ConnectTimeout=5 -L "${local_bind_host}:${local_bind_port}:${remote_target}" proxy || true
}

check_api() {
    curl -fsS --max-time 3 "${api_url}" >/dev/null 2>&1
}

while true; do
    ensure_tunnel
    if check_api; then
        fail_count=0
        backoff=5
    else
        fail_count=$((fail_count + 1))
        if (( fail_count >= max_fail )); then
            exit 1
        fi
    fi
    sleep "${backoff}"
    if (( backoff < backoff_max )); then
        backoff=$((backoff * 2))
        (( backoff > backoff_max )) && backoff="${backoff_max}"
    fi
done
EOS
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENV PATH="/usr/local/bin:${PATH}"
USER 1000:1000
ENTRYPOINT ["docker-entrypoint.sh"]
EOF

    cat > "$outdir/docker-compose.yaml" <<'YAML'
name: frontend
services:
  nginx:
    build:
      context: ./nginx
    image: nginx-acme:latest
    pull_policy: never
    container_name: frontend_nginx
    runtime: runc
    restart: unless-stopped
    logging: { driver: none }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1"]
      interval: 5s
      timeout: 3s
      retries: 60
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - frontend_nginx_config:/etc/nginx:ro
      - frontend_nginx_html:/usr/share/nginx/html:ro
      - frontend_acme_state:/var/cache/nginx/acme/state
    security_opt:
      - apparmor:docker-frontend-nginx
      - seccomp=/etc/docker/seccomp-frontend.json
    networks:
      frontend_internal:
        ipv4_address: ${docker_internal_nginx_ipv4}
      frontend_external:
        ipv4_address: ${docker_external_nginx_ipv4}

  tunnel:
    build:
      context: ./tunnel
      args:
        docker_internal_tunnel_ipv4: "${docker_internal_tunnel_ipv4}"
    image: tunnel:latest
    pull_policy: never
    container_name: frontend_tunnel
    runtime: runsc
    restart: always
    logging: { driver: none }
    volumes:
      - frontend_tunnel:/ssh:ro
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
    healthcheck:
      test: ["CMD", "ssh", "-q", "-F", "/ssh/config", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-O", "check", "proxy"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 30s
    security_opt:
      - apparmor:docker-frontend-tunnel
      - seccomp=/etc/docker/seccomp-frontend.json
    networks:
      frontend_internal:
        ipv4_address: ${docker_internal_tunnel_ipv4}
      frontend_external:
        ipv4_address: ${docker_external_tunnel_ipv4}

networks:
  frontend_internal:
    name: frontend_internal
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${docker_internal_subnet_ipv4}
          gateway: ${docker_internal_gw_ipv4}
  frontend_external:
    name: frontend_external
    driver: bridge
    ipam:
      config:
        - subnet: ${docker_external_subnet_ipv4}
          gateway: ${docker_external_gw_ipv4}

volumes:
  frontend_nginx_config:
    external: true
  frontend_nginx_html:
    external: true
  frontend_acme_state:
    external: true
  frontend_tunnel:
    external: true
YAML

    mkdir -p "$final_out_dir"
    tar -C "$pkg_root" -cJf "$final_tar_path" data
    info "Package created: ${final_tar_path}"
}

# ───────────── main ─────────────
main() {
    check_pkg
    preflight_cleanup
    clear_scr
    prompt_domain_and_archive_url
    clear_scr
    local deploy_env
    deploy_env="$(prompt_deploy_token)" || die "Failed to decode Deploy Token"
    eval "$deploy_env"

    docker_internal_subnet_ipv4='172.37.0.0/24'
    docker_external_subnet_ipv4='172.38.0.0/24'
    local int_pref ext_pref
    int_pref="${docker_internal_subnet_ipv4%/*}"
    ext_pref="${docker_external_subnet_ipv4%/*}"
    int_pref="${int_pref%.*}."
    ext_pref="${ext_pref%.*}."
    docker_internal_gw_ipv4="${int_pref}1"
    docker_internal_nginx_ipv4="${int_pref}2"
    docker_internal_tunnel_ipv4="${int_pref}3"
    docker_external_gw_ipv4="${ext_pref}1"
    docker_external_nginx_ipv4="${ext_pref}2"
    docker_external_tunnel_ipv4="${ext_pref}3"

    create_volumes
    seed_tunnel_volume
    seed_nginx_frontend
    make_package
    final_cleanup
}

if [[ "${BASH_SOURCE[0]-$0}" == "$0" ]]; then
    main "$@"
fi
