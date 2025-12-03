#!/bin/bash
set -Eeuo pipefail

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
        err "Or: unset DOCKER_HOST ; docker context use default"
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
compose_up_flag=0
keep_on_fail="${KEEP_ON_FAIL:-0}"
declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image() { _tmp_images+=("$1"); }
tmp_folder="$(mktemp -d -t matrix-session.XXXXXXXX)"
append_tmp_dir "$tmp_folder"
runtime_dir="${tmp_folder}/runtime"
mkdir -p "$runtime_dir"

make_tmp_dir() {
    local d
    d="$(mktemp -d "${tmp_folder}/d.XXXXXXXX")"
    printf '%s\n' "$d"
}
make_tmp_file() {
    local f
    f="$(mktemp "${tmp_folder}/f.XXXXXXXX")"
    append_tmp_file "$f"
    printf '%s\n' "$f"
}
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
__compose() {
    if ${SUDO:-} docker compose version >/dev/null 2>&1; then
        ${SUDO:-} docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        ${SUDO:-} docker-compose "$@"
    else
        err "docker compose is not available."
        return 1
    fi
}
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
preclean_patterns() {
    for name in matrix_synapse matrix_postgres matrix_redis matrix_tunnel; do
        ${SUDO:-} docker ps -aq -f "name=^${name}$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^matrix_(internal|external)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^matrix_(synapse|postgres|tunnel|redis)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    prune_build_caches
}

guard_pid=""

start_session_guard() {
    local proj="$1"
    local yml="$2"
    local parent="$$"
    local tty_path

    tty_path="$(tty 2>/dev/null || true)"

    mkdir -p "${tmp_folder}/${proj}"
    local guard="${tmp_folder}/${proj}/._guard.sh"
    local pidfile="${tmp_folder}/${proj}/._guard.pid"

    cat >"$guard" <<'EOS'
#!/bin/bash
set -Eeuo pipefail

proj="$1"
yml="$2"
parent="$3"
tty_path="${4:-}"

on_term() {
    if [[ -f "$yml" ]]; then
        ${SUDO:-} docker compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in matrix_synapse matrix_postgres matrix_redis matrix_tunnel; do
        ${SUDO:-} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r:-} ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^matrix_(internal|external)$" | xargs ${xargs_r:-} ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^matrix_(synapse|postgres|tunnel|redis)$" | xargs ${xargs_r:-} ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
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

    local i
    for i in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            unset guard_pid
            return 0
        fi
        sleep 0.2
    done

    kill -KILL "$pid" 2>/dev/null || true
    unset guard_pid
}
cleanup_docker_stack() {
    set +e

    if (( compose_up_flag )); then
        if [[ -n "${tmp_compose:-}" && -f "${tmp_compose:-}" ]]; then
            if [[ -n "${tmp_env:-}" && -f "${tmp_env:-}" ]]; then
                __compose --env-file "$tmp_env" -f "$tmp_compose" -p matrix down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
            else
                __compose -f "$tmp_compose" -p matrix down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
            fi
        fi
    fi

    ${SUDO:-} docker ps -aq -f "name=^matrix_(synapse|postgres|redis|tunnel)$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^matrix_(internal|external)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^matrix_(synapse|postgres|tunnel|redis)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    set -e
}
remove_images_by_ref() {
    local ref="$1"
    ${SUDO:-} docker images -q --filter "reference=${ref}" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
}
purge_runtime_images() {
    ${SUDO:-} docker images -q --filter "reference=deploy-token-prompter:*" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    ${SUDO:-} docker images -q --filter "reference=gh-nicks:*" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    ${SUDO:-} docker images -q --filter "reference=tunnel:latest" | xargs $xargs_r ${SUDO:-} docker rmi -f >/dev/null 2>&1 || true
    remove_images_by_ref "alpine:latest"
    remove_images_by_ref "postgres:18-alpine"
    remove_images_by_ref "redis:8-alpine"
    remove_images_by_ref "matrixdotorg/synapse:latest"
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

    rm -f /tmp/matrix-compose.run.*.yaml 2>/dev/null || true
    rm -rf /tmp/synseed.* /tmp/matrix-pkg.* /tmp/matrix-vols.* /tmp/matrix-restore.* 2>/dev/null || true

    if [[ -n "${tmp_folder:-}" && -d "${tmp_folder:-}" ]]; then
        rm -rf -- "${tmp_folder}" 2>/dev/null || true
    fi
}
cleanup_all() {
    set +e
    set +u

    if [[ "${KEEP_ON_FAIL:-0}" = "1" ]]; then
        info "KEEP_ON_FAIL=1 -> skip cleanup for debugging"
        sudo_keepalive_stop
        stop_session_guard
        set -e
        set -u
        return 0
    fi

    stop_session_guard
    cleanup_docker_stack
    cleanup_files
    cleanup_images
    sudo_keepalive_stop

    set -e
    set -u
}

sudo_keepalive_start 90
trap 'cleanup_all; exit 130' INT TERM HUP
trap 'cleanup_all' EXIT
preclean_patterns

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
                curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg \
                    | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
                sudo sh -c "printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.gpg\n' \
                    '$codename' '$arch' > /etc/apt/sources.list.d/docker.sources"
                sudo sh -c "printf 'Package: *\nPin: origin download.docker.com\nPin-Priority: 900\n' \
                    > /etc/apt/preferences.d/docker"
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
read_large_line_from_tty() {
    local prompt="$1"
    local __outvar="$2"
    local line=""
    local old_stty=""

    if [[ -t 0 && -t 1 ]]; then
        if ! old_stty="$(stty -g </dev/tty 2>/dev/null)"; then
            return 1
        fi

        while :; do
            printf '%s' "$prompt" > /dev/tty
            stty -icanon min 1 time 0 </dev/tty

            if ! IFS= read -r line </dev/tty; then
                stty "$old_stty" </dev/tty 2>/dev/null || true
                return 1
            fi

            line="${line%$'\r'}"
            line="${line%$'\n'}"

            if [[ -n "$line" ]]; then
                break
            fi

            clear_scr
            err "Users Token cannot be empty. Try again."
        done

        stty "$old_stty" </dev/tty 2>/dev/null || true
    else
        IFS= read -r line || return 1
        line="${line%$'\r'}"
        line="${line%$'\n'}"
    fi

    printf -v "$__outvar" '%s' "$line"
}
prompt_users_mode_and_token() {
    local choice
    USERS_MODE=""
    USERS_TOKEN=""

    echo
    echo "1. Restore users from backup."
    echo "2. Create new users."

    while :; do
        printf "?: "
        if ! IFS= read -r choice </dev/tty; then
            die "failed to read choice from TTY"
        fi

        case "$choice" in
            1)
                USERS_MODE="restore"
                break
                ;;
            2|"")
                USERS_MODE="create"
                break
                ;;
            *)
                err "Invalid choice, enter 1 or 2."
                ;;
        esac
    done

    if [[ "$USERS_MODE" == "restore" ]]; then
        echo
        printf "Paste Restore Users Token"
        read_large_line_from_tty ": " USERS_TOKEN || die "failed to read Users Token"
        if [[ -z "$USERS_TOKEN" ]]; then
            die "Users Token is empty."
        fi
    fi
}
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
prompt_matrix_config() {
    local matrix_server_name invite_count room_name target
    clear_screen() {
        clear 2>/dev/null || true
        printf '\e[3J' 2>/dev/null || true
    }
    confirm_and_proceed() {
        local prompt="$1" a
        while true; do
            printf "%s (y/n/cancel): " "$prompt" >&2
            read -r a
            case "$a" in
                y|Y|yes|Yes) return 0 ;;
                n|N|no|No)   return 1 ;;
                cancel|Cancel) return 2 ;;
                *) echo "Enter y, n, or cancel." >&2 ;;
            esac
        done
    }
    get_matrix_server_name() {
        clear_screen
        while true; do
            printf "Enter the Matrix server name (default: 'example'): " >&2
            IFS= read -r matrix_server_name
            if [[ -z "$matrix_server_name" ]]; then
                matrix_server_name="example"
                echo "Using default: '$matrix_server_name'" >&2
            fi
            printf "You entered '%s'. Confirm? (y/n/cancel): " "$matrix_server_name" >&2
            IFS= read -r c
            case "$c" in
                y|Y|yes|Yes) break ;;
                n|N|no|No) echo "Try again." >&2 ;;
                cancel|Cancel) echo "Operation canceled." >&2; exit 1 ;;
                *) echo "Enter 'y', 'n', or 'cancel'." >&2 ;;
            esac
        done
    }
    get_invite_count() {
        clear_screen
        while true; do
            printf "How many users need to create a separate room for? (default: 3): " >&2
            IFS= read -r invite_count
            if [[ -z "$invite_count" ]]; then
                invite_count=3
                echo "Using default invite count: $invite_count" >&2
            elif [[ ! "$invite_count" =~ ^[0-9]+$ ]]; then
                echo "Enter a positive number." >&2
                continue
            fi
            printf "You entered '%s'. Confirm? (y/n/cancel): " "$invite_count" >&2
            IFS= read -r c
            case "$c" in
                y|Y|yes|Yes) break ;;
                n|N|no|No) echo "Try again." >&2 ;;
                cancel|Cancel) echo "Operation canceled." >&2; exit 1 ;;
                *) echo "Enter 'y', 'n', or 'cancel'." >&2 ;;
            esac
        done
    }
    get_room_name() {
        clear_screen
        while true; do
            printf "Enter the name of the separate room for %s users. (default: 'meeting'): " "$invite_count" >&2
            IFS= read -r room_name
            if [[ -z "$room_name" ]]; then
                room_name="meeting"
                echo "Using default: '$room_name'" >&2
            fi
            printf "You entered '%s'. Confirm? (y/n/cancel): " "$room_name" >&2
            IFS= read -r c
            case "$c" in
                y|Y|yes|Yes) break ;;
                n|N|no|No) echo "Try again." >&2 ;;
                cancel|Cancel) echo "Operation canceled." >&2; exit 1 ;;
                *) echo "Enter 'y', 'n', or 'cancel'." >&2 ;;
            esac
        done
    }
    get_target_count() {
        clear_screen
        while true; do
            printf "How many users to generate? (default: 30): " >&2
            IFS= read -r target
            [[ -z "$target" ]] && target=30
            if [[ "$target" =~ ^[0-9]+$ && "$target" -ge 1 ]]; then
                printf "You entered '%s'. Confirm? (y/n/cancel): " "$target" >&2
                IFS= read -r c
                case "$c" in
                    y|Y|yes|Yes) break ;;
                    n|N|no|No) echo "Try again." >&2 ;;
                    cancel|Cancel) echo "Operation canceled." >&2; exit 1 ;;
                    *) echo "Enter 'y', 'n', or 'cancel'." >&2 ;;
                esac
            else
                echo "Enter a positive integer." >&2
            fi
        done
    }
    main_prompter() {
        exec 3>&1
        exec 1>&2

        while true; do
            clear_screen
            get_matrix_server_name
            get_invite_count
            get_room_name
            get_target_count
            clear_screen

            echo "Parameters:"
            echo "  Matrix server name:      $matrix_server_name"
            echo "  Room name:               $room_name"
            echo "  Invited users to room:   $invite_count"
            echo "  Users to create:         $target"

            confirm_and_proceed "Proceed?"
            case $? in
                0)
                    printf 'target="%s"\n' "${target:-}" >&3
                    printf 'matrix_server_name="%s"\n' "${matrix_server_name:-}" >&3
                    printf 'invite_count="%s"\n' "${invite_count:-}" >&3
                    printf 'room_name="%s"\n' "${room_name:-}" >&3
                    return 0
                    ;;
                1)
                    unset target matrix_server_name invite_count room_name
                    continue
                    ;;
                2)
                    echo "Cancelled." >&2
                    exit 1
                    ;;
            esac
        done
    }

    main_prompter
}

final_slug="$( (command -v uuidgen >/dev/null 2>&1 && uuidgen || cat /proc/sys/kernel/random/uuid) | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]' )"
final_out_dir="${FINAL_TAR_DIR:-$HOME/Downloads/matrix}"
final_tar_path="${FINAL_TAR:-${final_out_dir}/${final_slug}.tar.xz}"

generate_users_data() {
    image="${image:-gen-users-data:alpine-$$_$(date +%s)}"
    append_tmp_image "$image"
    minlen="${minlen:-8}"
    minalpha="${minalpha:-7}"
    digit_pct="${digit_pct:-40}"
    maxdigits="${maxdigits:-2}"

    local __bash_major=${BASH_VERSINFO[0]:-3}
    local __has_assoc=0
    if (( __bash_major >= 4 )); then
        __has_assoc=1
    fi

    if (( __has_assoc )); then
        declare -A users_data=()
        users_data_order=()
        matrix_users_array=()
        display_names_array=()
        matrix_passwords_array=()
    else
        users_data=
        users_data_order=()
        matrix_users_array=()
        display_names_array=()
        matrix_passwords_array=()
    fi

cat <<'dockerfile' | ${SUDO:-} docker build -t "${image}" - >/dev/null
FROM alpine:latest
RUN apk add --no-cache bash curl jq gzip coreutils tor ca-certificates netcat-openbsd && update-ca-certificates
RUN cat <<'SH' > /usr/local/bin/run.sh
#!/bin/bash
set -Eeuo pipefail

declare -a _tmp_files=()
_register_tmp() { [[ -n "${1:-}" ]] && _tmp_files+=("$1"); }
_cleanup() {
    local f
    if [[ -n "${TOR_PID:-}" ]]; then kill "$TOR_PID" >/dev/null 2>&1 || true; fi
    if [[ ${_tmp_files+x} ]]; then
        for f in "${_tmp_files[@]}"; do
            [[ -n "$f" ]] && rm -f "$f" >/dev/null 2>&1 || true
        done
    fi
}
on_int() { _cleanup; exit 130; }
on_term() { _cleanup; exit 143; }
on_hup() { _cleanup; exit 129; }
trap on_int  INT
trap on_term TERM
trap on_hup  HUP
trap _cleanup EXIT

TOR_RETRIES="${tor_retries:-3}"
TOR_BOOTSTRAP_TIMEOUT="${tor_bootstrap_timeout:-90}"

command -v tor >/dev/null 2>&1 || { echo "Tor not found"; exit 9; }

start_tor() {
    local attempt="$1"
    rm -rf "/tmp/tor-$attempt" && mkdir -p "/tmp/tor-$attempt"
    tor \
      --ClientOnly 1 \
      --SocksPort 127.0.0.1:9050 \
      --ControlPort 127.0.0.1:9051 \
      --CookieAuthentication 0 \
      --AvoidDiskWrites 1 \
      --DataDirectory "/tmp/tor-$attempt" \
      --Log "notice stderr" >/dev/null 2>&1 &
    TOR_PID=$!
    sleep 0.5
    kill -0 "$TOR_PID" 2>/dev/null || { echo "Tor failed to start"; exit 9; }
}

ctrl() {
    local IFS=$'\n'
    printf '%s\r\n' "$@" | nc -w 2 127.0.0.1 9051
}

wait_tor_ready() {
    local deadline=$(( $(date +%s) + TOR_BOOTSTRAP_TIMEOUT ))
    local resp
    while (( $(date +%s) < deadline )); do
        resp="$(ctrl 'AUTHENTICATE ""' 'GETINFO status/bootstrap-phase' 'QUIT' 2>/dev/null || true)"
        if echo "$resp" | grep -q 'PROGRESS=100'; then
            if curl -sS -I --connect-timeout 5 -m 8 --proto '=https' --http2 --socks5-hostname 127.0.0.1:9050 https://data.gharchive.org/ >/dev/null 2>&1; then
              return 0
            fi
        fi
        kill -0 "$TOR_PID" 2>/dev/null || return 1
        sleep 1
    done
    return 1
}

boot_ok=0
for a in $(seq 1 "$TOR_RETRIES"); do
    start_tor "$a"
    if wait_tor_ready; then boot_ok=1; break; fi
    kill "$TOR_PID" >/dev/null 2>&1 || true
    sleep 2
done

if (( ! boot_ok )); then
    echo "Tor bootstrap timeout"
    exit 9
fi

PROXY=(--proxy socks5h://127.0.0.1:9050)

target="${target:-20}"
minlen="${minlen:-8}"
minalpha="${minalpha:-7}"
digit_pct="${digit_pct:-30}"
maxdigits="${maxdigits:-2}"
min_sleep_success="${min_sleep_success:-1.8}"
max_sleep_success="${max_sleep_success:-3.7}"
sleep_on_429_min="${sleep_on_429_min:-15}"
sleep_on_429_max="${sleep_on_429_max:-30}"
sleep_on_403_min="${sleep_on_403_min:-60}"
sleep_on_403_max="${sleep_on_403_max:-120}"
backoff_base="${backoff_base:-1.6}"
backoff_max="${backoff_max:-60}"
max_retry_per_url="${max_retry_per_url:-3}"
connect_timeout="${connect_timeout:-12}"
read_timeout="${read_timeout:-45}"
year_min="${year_min:-2014}"
year_max="${year_max:-2024}"
hour_min="${hour_min:-12}"
hour_max="${hour_max:-22}"
max_hours="${max_hours:-120}"
max_bytes="${max_bytes:-104857600}"
max_404="${max_404:-50}"
min_gz_bytes="${min_gz_bytes:-3000000}"

pairs="/tmp/pairs.tsv"
plain="/tmp/plain.tsv"
digit="/tmp/digit.tsv"
visited="/tmp/visited_urls.txt"
: > "${pairs}"
: > "${visited}"

fetched_hours=0
downloaded_bytes=0
seen_404=0

pick() { shuf -i "$1"-"$2" -n 1; }

jitter_sleep() {
    local min="$1" max="$2" dur
    dur="$(awk -v a="$min" -v b="$max" 'BEGIN{srand(); printf "%.3f", (a + (b-a)*rand()) }')"
    sleep "$dur"
}

generate_http_headers() {
    local -a user_agents=(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/90.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 11; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Mobile Safari/537.36"
        "Mozilla/5.0 (X11; CrOS x86_64 13729.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (Linux; Android 11; SM-T860) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; Nexus 6P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
    )
    local idx=$(( RANDOM % ${#user_agents[@]} ))
    local ua="${user_agents[$idx]}"
    local header_string=""
    if [[ "$ua" == *"Chrome"* && "$ua" != *"Edge"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    elif [[ "$ua" == *"Firefox"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    else
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    fi
    echo "$header_string"
}

header_string="$(generate_http_headers)"
eval "set -- ${header_string}"
hdr_args=( "$@" )

fetch_with_pacing() {
    local url="$1" out="$2"
    local attempt=0
    local backoff="${backoff_base}"
    local code size_ok head_code clen got

    while (( attempt <= max_retry_per_url )); do
        head_code="$(curl -sS -I --http2 --tlsv1.3 --proto '=https' --connect-timeout "${connect_timeout}" -m 10 "${hdr_args[@]}" "${PROXY[@]}" -D /tmp/h -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true)"
        case "${head_code}" in
            200) : ;;
            404) jitter_sleep 1 3; return 4 ;;
            429) jitter_sleep "${sleep_on_429_min}" "${sleep_on_429_max}"; attempt=$((attempt+1)); continue ;;
            403) jitter_sleep "${sleep_on_403_min}" "${sleep_on_403_max}"; attempt=$((attempt+1)); continue ;;
            000) jitter_sleep 1 3; attempt=$((attempt+1)); continue ;;
              *) jitter_sleep "${backoff}" "$(awk -v b="${backoff}" 'BEGIN{printf "%.3f", b+1}')"
                 backoff="$(awk -v b="${backoff}" -v m="${backoff_max}" 'BEGIN{b=b*1.7; if(b>m)b=m; printf "%.3f", b}')"
                 attempt=$((attempt+1)); continue ;;
        esac

        clen=$(awk -F': ' 'tolower($1)=="content-length"{gsub("\r","",$2);print $2}' /tmp/h)
        if [ -n "${clen}" ] && [ "${clen}" -lt "${min_gz_bytes}" ]; then
            return 4
        fi

        code="$(curl -sS --http2 --tlsv1.3 --proto '=https' --connect-timeout "${connect_timeout}" -m "${read_timeout}" "${hdr_args[@]}" "${PROXY[@]}" -o "${out}" -w '%{http_code}' --location "${url}" 2>/dev/null || true)"

        size_ok=0
        if [[ -s "${out}" ]]; then
            if [ -n "${clen}" ]; then
              got=$(wc -c < "${out}")
              [ "${got}" -eq "${clen}" ] || { rm -f "${out}"; jitter_sleep 1 3; attempt=$((attempt+1)); continue; }
            fi
            if ! gzip -t "${out}" 2>/dev/null; then
              rm -f "${out}"; jitter_sleep 1 3; attempt=$((attempt+1)); continue
            fi
            size_ok=1
        fi

        if [[ "${code}" == "200" && "${size_ok}" -eq 1 ]]; then
            jitter_sleep "${min_sleep_success}" "${max_sleep_success}"
            return 0
        fi

        case "${code}" in
            404) jitter_sleep 2 5; return 4 ;;
            429) jitter_sleep "${sleep_on_429_min}" "${sleep_on_429_max}" ;;
            403) jitter_sleep "${sleep_on_403_min}" "${sleep_on_403_max}" ;;
            000) jitter_sleep 1 3 ;;
              *) jitter_sleep "${backoff}" "$(awk -v b="${backoff}" 'BEGIN{printf "%.3f", b+1}')"
                 backoff="$(awk -v b="${backoff}" -v m="${backoff_max}" 'BEGIN{b=b*1.7; if(b>m)b=m; printf "%.3f", b}')"
                 ;;
        esac
        attempt=$(( attempt + 1 ))
    done

    return 1
}

need_digit=$(( (target * digit_pct + 50) / 100 ))
(( need_digit > target )) && need_digit="${target}"
need_plain=$(( target - need_digit ))

while :; do
    if (( fetched_hours >= max_hours )) || (( downloaded_bytes >= max_bytes )) || (( seen_404 >= max_404 )); then
        break
    fi

    y=$(pick "${year_min}" "${year_max}")
    m=$(printf "%02d" "$(pick 1 12)")
    d=$(printf "%02d" "$(pick 1 28)")
    h=$(printf "%02d" "$(pick "${hour_min}" "${hour_max}")")
    u="https://data.gharchive.org/${y}-${m}-${d}-${h}.json.gz"
    f="/tmp/e.json.gz"

    if grep -qxF "${u}" "${visited}" 2>/dev/null; then
        jitter_sleep 0.3 0.8
        continue
    fi
    echo "${u}" >> "${visited}"

    rc=0
    if ! fetch_with_pacing "${u}" "${f}"; then
        rc=$?
        if [[ "${rc}" -eq 4 ]]; then
            seen_404=$(( seen_404 + 1 ))
        fi
        continue
    fi

    if [[ -s "${f}" ]]; then
        sz="$(wc -c < "${f}")"
        downloaded_bytes=$(( downloaded_bytes + sz ))
        fetched_hours=$(( fetched_hours + 1 ))
        if [ "${fetched_hours}" -eq 10 ]; then hour_min=0; hour_max=23; fi
    fi

    gzip -dc "${f}" 2>/dev/null | jq -r '
      select(type=="object")
      | . as $e
      | (
          if ($e.actor_attributes and ($e.actor_attributes.login // empty) and ($e.actor_attributes.name // empty)) then
            [($e.actor_attributes.login|tostring), ($e.actor_attributes.name|tostring)]

          elif (($e.actor|type)=="object")
               and ($e.actor.login // empty)
               and (($e.payload.commits|type)=="array") then
            $e.payload.commits[]
            | select(.author and .author.name)
            | [($e.actor.login|tostring), (.author.name|tostring)]

          elif (($e.actor|type)=="object")
               and ($e.actor.login // empty)
               and (($e.payload|type)=="object")
               and (($e.payload.head_commit|type)=="object")
               and (($e.payload.head_commit.author|type)=="object")
               and ($e.payload.head_commit.author.name // empty) then
            [($e.actor.login|tostring), ($e.payload.head_commit.author.name|tostring)]

          elif (($e.actor|type)=="object")
               and ($e.actor.login // empty)
               and (($e.payload|type)=="object")
               and (($e.payload.pusher|type)=="object")
               and ($e.payload.pusher.name // empty) then
            [($e.actor.login|tostring), ($e.payload.pusher.name|tostring)]

          elif (($e.actor|type)=="string") then
            [($e.actor|tostring), ""]
          else empty end
        )
      | @tsv
    ' 2> /tmp/jq_error.log | \
    LC_ALL=C awk -F '\t' -v minlen="${minlen}" -v minalpha="${minalpha}" -v maxdigits="${maxdigits}" '
      BEGIN{
        IGNORECASE=1
        bad="(^|[[:space:]])(bot|dependabot|renovate|actions?|ci|build|release|auto|automation|upptime|txms|robot|crawler|sync)([[:space:]]|$)"
      }
      function trim(s){gsub(/^[ \t\r\n]+|[ \t\r\n]+$/,"",s); return s}
      function capw(s){return toupper(substr(s,1,1)) tolower(substr(s,2))}
      function cntdig(s){t=s; return gsub(/[0-9]/,"",t)}
      function cntalp(s){t=s; return gsub(/[a-z]/,"",t)}
      {
        nick=tolower($1)
        name=trim($2)
        gsub(/[^A-Za-z ]/,"",name)
        gsub(/[[:space:]]+/," ",name); name=trim(name)

        if (nick !~ /^[a-z0-9]+$/) next
        if (length(nick) < minlen) next

        d = cntdig(nick); a = cntalp(nick)
        if (a < minalpha) next
        if (!(d == 0 || (d >= 1 && d <= maxdigits))) next

        low=tolower(name)
        if (low ~ bad) next

        n=split(name, w, / /)
        if (n==2 && w[1] ~ /^[A-Za-z]+$/ && w[2] ~ /^[A-Za-z]+$/) {
          first=capw(w[1]); last=capw(w[2]); pretty=first " " last
        } else if (n==3 && w[1] ~ /^[A-Za-z]+$/ && w[2] ~ /^[A-Za-z]$/ && w[3] ~ /^[A-Za-z]+$/) {
          first=capw(w[1]); mid=toupper(w[2]); last=capw(w[3]); pretty=first " " mid " " last
        } else {
          next
        }

        l=tolower(pretty)
        if (seen_login[nick]++) next
        if (seen_name[l]++) next

        print nick "\t" pretty
      }
    ' >> "${pairs}"

    awk -F '\t' 'BEGIN{IGNORECASE=1} !seen_login[$1]++ && !seen_name[$2]++' "${pairs}" > "${pairs}.u" && mv "${pairs}.u" "${pairs}"

    : > "${plain}"; : > "${digit}"
    awk -F '\t' -v maxdigits="${maxdigits}" '
      BEGIN{IGNORECASE=1}
      function cntdig(s){t=s; return gsub(/[0-9]/,"",t)}
      !seen_login[$1]++ && !seen_name[tolower($2)]++ {
        d=cntdig($1)
        if (d==0) print > "'"${plain}"'"
        else if (d>=1 && d<=maxdigits) print > "'"${digit}"'"
      }
    ' "${pairs}"

    have_plain=$(wc -l < "${plain}" 2>/dev/null || echo 0)
    have_digit=$(wc -l < "${digit}" 2>/dev/null || echo 0)
    total=$(( have_plain + have_digit ))
    if [ "${total}" -ge "${target}" ]; then
        if [ "${need_digit}" -gt "${have_digit}" ]; then
            need_digit="${have_digit}"
            need_plain=$(( target - need_digit ))
        fi
        break
    fi
done

tmpd="/tmp/dsel.tsv"; tmpp="/tmp/psel.tsv"
shuf -n "${need_digit}" "${digit}" > "${tmpd}" || true
shuf -n "${need_plain}" "${plain}" > "${tmpp}" || true

sched="/tmp/sched.txt"
awk -v t="${target}" -v d="${need_digit}" 'BEGIN{
    for(i=1;i<=t;i++){
        cur = int(i*d/t)
        prev = int((i-1)*d/t)
        if (cur>prev) print "d"; else print "p";
    }
}' > "${sched}"

exec 3<"${tmpd}"
exec 4<"${tmpp}"

out="/tmp/final.tsv"
: > "${out}"

pw() { LC_ALL=C tr -dc 'A-Za-z0-9<>*+!' </dev/urandom | head -c 25 || true; }

while IFS= read -r kind; do
    if [ "${kind}" = "d" ]; then
        if IFS= read -r -u 3 line; then
            IFS=$'\t' read -r nick pretty <<<"$line"
            pass="$(pw)"
            printf '%s\t%s\t%s\n' "$nick" "$pretty" "$pass" >> "${out}"
        elif IFS= read -r -u 4 line; then
            IFS=$'\t' read -r nick pretty <<<"$line"
            pass="$(pw)"
            printf '%s\t%s\t%s\n' "$nick" "$pretty" "$pass" >> "${out}"
        fi
    else
        if IFS= read -r -u 4 line; then
            IFS=$'\t' read -r nick pretty <<<"$line"
            pass="$(pw)"
            printf '%s\t%s\t%s\n' "$nick" "$pretty" "$pass" >> "${out}"
        elif IFS= read -r -u 3 line; then
            IFS=$'\t' read -r nick pretty <<<"$line"
            pass="$(pw)"
            printf '%s\t%s\t%s\n' "$nick" "$pretty" "$pass" >> "${out}"
        fi
    fi
done < "${sched}"

ordered=()
if ! mapfile -t ordered < <(head -n "${target}" "${out}"); then
    ordered=()
fi

echo "### BEGIN IDX ###"
echo 'matrix_users_array=()'
echo 'display_names_array=()'
echo 'matrix_passwords_array=()'
for line in "${ordered[@]}"; do
    IFS=$'\t' read -r k v p <<<"${line}"
    printf 'matrix_users_array+=(%q)\n' "$k"
    printf 'display_names_array+=(%q)\n' "$v"
    printf 'matrix_passwords_array+=(%q)\n' "$p"
done
echo "### END IDX ###"

echo "### BEGIN ASSOC ###"
echo "declare -A users_data=()"
for line in "${ordered[@]}"; do
    IFS=$'\t' read -r k v p <<<"${line}"
    val="${v}"$'\t'"${p}"
    printf 'users_data[%q]=%q\n' "$k" "$val"
done
printf 'users_data_order=('
for line in "${ordered[@]}"; do
    IFS=$'\t' read -r k _ <<<"${line}"
    printf ' %q' "$k"
done
echo ' )'
echo "### END ASSOC ###"
SH

RUN chmod +x /usr/local/bin/run.sh
ENTRYPOINT ["/usr/local/bin/run.sh"]
dockerfile

    local gen
    gen="$(${SUDO:-} docker run --rm \
            -e target="${target}" \
            -e minlen="${minlen}" \
            -e minalpha="${minalpha}" \
            -e digit_pct="${digit_pct}" \
            -e maxdigits="${maxdigits}" \
            -e year_min="${year_min:-2012}" \
            -e year_max="${year_max:-2022}" \
            -e hour_min="${hour_min:-10}" \
            -e hour_max="${hour_max:-23}" \
            -e max_hours="${max_hours:-120}" \
            -e max_bytes="${max_bytes:-104857600}" \
            -e max_404="${max_404:-50}" \
            "${image}")" || return 1

    if (( __has_assoc )); then
        eval "$(printf '%s\n' "$gen" | sed -n '/^### BEGIN ASSOC ###$/,/^### END ASSOC ###$/p' | sed '1d;$d')"
        local u dname p
        for u in "${users_data_order[@]}"; do
            IFS=$'\t' read -r dname p <<<"${users_data[$u]}"
            matrix_users_array+=("$u")
            display_names_array+=("$dname")
            matrix_passwords_array+=("$p")
        done
    else
        eval "$(printf '%s\n' "$gen" | sed -n '/^### BEGIN IDX ###$/,/^### END IDX ###$/p' | sed '1d;$d')"
    fi
    ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
}
json_escape() {
    local s="${1-}"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}
build_users_payload() {
    {
        printf '{\n'
        printf '  "matrix_server_name": "%s",\n' "$(json_escape "${matrix_server_name:-}")"
        printf '  "room_name": "%s",\n' "$(json_escape "${room_name:-}")"
        printf '  "invite_count": %s,\n' "${invite_count:-0}"
        printf '  "users": [\n'

        local i last
        last=$(( ${#matrix_users_array[@]} - 1 ))
        for ((i=0; i<${#matrix_users_array[@]}; i++)); do
            local u="${matrix_users_array[$i]}"
            local d="${display_names_array[$i]}"
            local p="${matrix_passwords_array[$i]}"

            printf '    { "user": "%s", "display_name": "%s", "password": "%s" }' "$(json_escape "$u")" "$(json_escape "$d")" "$(json_escape "$p")"

            if (( i < last )); then
                printf ',\n'
            else
                printf '\n'
            fi
        done

        printf '  ]\n'
        printf '}\n'
    }
}
make_users_token_via_docker() {
    local image cname out
    image="users-token:alpine-$$_$(date +%s)"
    cname="matrix_users_token_$$"
    append_tmp_image "$image"

    cat <<'dockerfile' | ${SUDO:-} docker build -t "${image}" - >/dev/null
FROM alpine:latest
RUN apk add --no-cache bash xz coreutils gnupg pinentry-tty

RUN cat <<'SH' > /usr/local/bin/run.sh
#!/bin/bash
set -Eeuo pipefail

echo "[USERS_TOKEN] run.sh started" >&2

p="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 45 || true)"
echo "[USERS_TOKEN] generated pass length: ${#p}" >&2

payload="$(cat)"

if [[ -z "$payload" ]]; then
    echo "[USERS_TOKEN] empty payload on stdin" >&2
    exit 1
fi

payload_size="$(printf '%s' "$payload" | wc -c | awk '{print $1}')"
echo "[USERS_TOKEN] payload size (bytes): ${payload_size}" >&2

b64="$(printf '%s' "$payload" \
    | xz -9e \
    | gpg --batch --yes --no-tty --quiet \
          --pinentry-mode loopback \
          --symmetric \
          --cipher-algo AES256 \
          --s2k-digest-algo SHA512 \
          --s2k-mode 3 \
          --s2k-count 65011712 \
          --compress-algo none \
          --passphrase "$p" \
          --output - 2>/dev/null \
    | base64 -w 0)"

b64_len=${#b64}
echo "[USERS_TOKEN] b64 length: ${b64_len}" >&2

h="jA0ECQMK"
if [[ "${b64:0:${#h}}" == "$h" ]]; then
    t="${b64:${#h}}"
else
    echo "[USERS_TOKEN] bad gpg header" >&2
    exit 3
fi

token="${p}${t}"
echo "[USERS_TOKEN] final token length: ${#token}" >&2

printf '%s\n' "$token"
SH

RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
dockerfile

    out="$(
        build_users_payload | ${SUDO:-} docker run --rm --name "$cname" -i "${image}"
    )" || {
        err "failed to generate Users Token"
        ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
        return 1
    }

    ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
    printf '%s\n' "$out"
}

decode_users_token_via_docker() {
    local token="$1"
    local image cname script
    image="users-token-decode:alpine-$$_$(date +%s)"
    cname="matrix_users_decode_$$"
    append_tmp_image "$image"

    cat <<'dockerfile' | ${SUDO:-} docker build -t "${image}" - >/dev/null
FROM alpine:latest
RUN apk add --no-cache bash xz coreutils gnupg pinentry-tty jq

RUN cat <<'SH' > /usr/local/bin/run.sh
#!/bin/bash
set -Eeuo pipefail

token="${USERS_TOKEN:-}"

token="${token%\"}"; token="${token#\"}"
token="${token%\'}"; token="${token#\'}"
token="$(printf '%s' "$token" | tr -d '\r\n \t')"

if [[ -z "$token" ]]; then
    echo "echo \"empty users token\" >&2; return 1"
    exit 0
fi

hdr="jA0ECQMK"
tmp_bin="$(mktemp)"
tmp_json="$(mktemp)"

if (( ${#token} > 45 )) && [[ "${token:0:45}" =~ ^[A-Za-z0-9]{45}$ ]]; then
    pass="${token:0:45}"
    tail="${token:45}"
    if ! printf '%s' "${hdr}${tail}" | base64 -d 2>/dev/null | \
       gpg --batch --yes --no-tty --quiet --pinentry-mode loopback \
           --passphrase "$pass" --decrypt 2>/dev/null >"$tmp_bin"; then
        echo "echo \"users token decrypt failed\" >&2; return 1"
        rm -f "$tmp_bin" "$tmp_json" 2>/dev/null || true
        exit 0
    fi
else
    if ! printf '%s' "$token" | base64 -d >"$tmp_bin" 2>/dev/null; then
        echo "echo \"users token base64 decode failed\" >&2; return 1"
        rm -f "$tmp_bin" "$tmp_json" 2>/dev/null || true
        exit 0
    fi
fi

if xz -t "$tmp_bin" >/dev/null 2>&1; then
    if ! xz -dc <"$tmp_bin" >"$tmp_json" 2>/dev/null; then
        echo "echo \"users token xz decompress failed\" >&2; return 1"
        rm -f "$tmp_bin" "$tmp_json" 2>/dev/null || true
        exit 0
    fi
else
    cat <"$tmp_bin" >"$tmp_json"
fi

if ! jq -e '.users and .matrix_server_name' "$tmp_json" >/dev/null 2>&1; then
    echo "echo \"users token JSON invalid\" >&2; return 1"
    rm -f "$tmp_bin" "$tmp_json" 2>/dev/null || true
    exit 0
fi

matrix_server_name="$(jq -r '.matrix_server_name' "$tmp_json")"
room_name="$(jq -r '.room_name // "meeting"' "$tmp_json")"
invite_count="$(jq -r '.invite_count // 0' "$tmp_json")"
users_count="$(jq -r '.users | length' "$tmp_json")"

echo "matrix_server_name=$(printf '%q' "$matrix_server_name")"
echo "room_name=$(printf '%q' "$room_name")"
echo "invite_count=$(printf '%q' "$invite_count")"
echo "target=$(printf '%q' "$users_count")"
echo "users_token=$(printf '%q' "$token")"

echo "matrix_users_array=()"
echo "display_names_array=()"
echo "matrix_passwords_array=()"

jq -r '.users[] | [.user, .display_name, .password] | @tsv' "$tmp_json" | \
while IFS=$'\t' read -r u d p; do
    printf 'matrix_users_array+=(%q)\n' "$u"
    printf 'display_names_array+=(%q)\n' "$d"
    printf 'matrix_passwords_array+=(%q)\n' "$p"
done

rm -f "$tmp_bin" "$tmp_json" 2>/dev/null || true
SH

RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
dockerfile

    script="$(
        ${SUDO:-} docker run --rm --name "$cname" -e USERS_TOKEN="$token" "${image}"
    )" || {
        err "failed to decode Users Token"
        ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
        return 1
    }

    ${SUDO:-} docker rmi -f "${image}" >/dev/null 2>&1 || true
    eval "$script"
}

# ───────────────────────── runtime / docker ───────────────────────
create_volumes() {
    info "Creating volumes (redis has no volume)"
    ${SUDO:-} docker volume create matrix_synapse >/dev/null 2>&1
    ${SUDO:-} docker volume create matrix_postgres >/dev/null 2>&1
    ${SUDO:-} docker volume create matrix_tunnel >/dev/null 2>&1
}
seed_tunnel_volume() {
    info "Seeding tunnel volume"
    local t
    t="$(mktemp -d "${tmp_folder}/tunnelseed.XXXXXXXX")"
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

    ${SUDO:-} docker run --rm \
        -v matrix_tunnel:/ssh \
        -v "$t":/src:ro \
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
seed_synapse_config() {
    info "Seeding production Synapse config into volume"
    postgres_db="$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 12 || true)"
    postgres_user="$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 10 || true)"
    postgres_password_runtime="$( (command -v uuidgen >/dev/null 2>&1 && uuidgen || cat /proc/sys/kernel/random/uuid) | tr '[:upper:]' '[:lower:]')"
    registration_shared_key="$(openssl rand -hex 32)"
    macaroon_secret_key="$(openssl rand -hex 32)"
    form_secret_key="$(openssl rand -hex 32)"
    matrix_http_port="8008"

    local tdir="$(mktemp -d "${tmp_folder}/synseed.XXXXXXXX")" || die "mktemp failed"
    local hs="${tdir}/homeserver.yaml"
    local lc="${tdir}/${matrix_server_name}.log.config"

    cat > "${hs}" <<EOF
account_threepid_delegates:
  msisdn: ''
alias_creation_rules:
  - action: allow
    alias: '*'
    room_id: '*'
    user_id: '*'
allow_guest_access: false
allow_public_rooms_over_federation: false
allow_public_rooms_without_auth: false
app_service_config_files: []
autocreate_auto_join_rooms: true
bcrypt_rounds: 13
caches:
  global_factor: 0.5
cas_config: null
database:
  args:
    cp_max: 10
    cp_min: 5
    database: ${postgres_db}
    host: ${docker_internal_postgres_ipv4}
    password: ${postgres_password_runtime}
    port: 5432
    user: ${postgres_user}
  name: psycopg2
  txn_limit: 0
default_room_version: '12'
enable_media_repo: true
enable_metrics: false
enable_registration: false
enable_registration_captcha: false
enable_registration_without_verification: false
enable_room_list_search: false
encryption_enabled_by_default_for_room_type: all
event_cache_size: 100K
form_secret: "${form_secret_key}"
include_profile_data_on_invite: false
ip_range_blacklist:
  - 127.0.0.0/8
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 100.64.0.0/10
  - 192.0.0.0/24
  - 169.254.0.0/16
  - 192.88.99.0/24
  - 198.18.0.0/15
  - 192.0.2.0/24
  - 198.51.100.0/24
  - 203.0.113.0/24
  - 224.0.0.0/4
  - ::1/128
  - fe80::/10
  - fc00::/7
  - 2001:db8::/32
  - ff00::/8
limit_profile_requests_to_users_who_share_rooms: false
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: false
    bind_addresses:
      - '${docker_internal_synapse_ipv4}'
      - '127.0.0.1'
    resources:
      - names: [client]
        compress: false
log_config: "/data/${matrix_server_name}.log.config"
macaroon_secret_key: "${macaroon_secret_key}"
max_spider_size: 10M
max_upload_size: 50M
media_store_path: "/data/media"
password_config:
  localdb_enabled: true
pid_file: "/data/matrix-synapse.pid"
presence:
  enabled: false
push:
  include_content: false
rc_admin_redaction: { burst_count: 50, per_second: 1 }
rc_federation: { concurrent: 3, reject_limit: 50, sleep_delay: 500, sleep_limit: 10, window_size: 1000 }
rc_invites:
  per_issuer: { burst_count: 10, per_second: 0.3 }
  per_room: { burst_count: 10, per_second: 0.3 }
  per_user: { burst_count: 5,  per_second: 0.003 }
rc_joins:
  local: { burst_count: 10, per_second: 0.1 }
  remote: { burst_count: 10, per_second: 0.01 }
rc_login:
  account: { burst_count: 3, per_second: 0.17 }
  address: { burst_count: 3, per_second: 0.17 }
  failed_attempts: { burst_count: 3, per_second: 0.17 }
rc_message: { burst_count: 10, per_second: 0.2 }
rc_registration: { burst_count: 3,  per_second: 0.17 }
redaction_retention_period: 7d
redis:
  enabled: true
  host: ${docker_internal_redis_ipv4}
  port: 6379
registration_requires_token: false
registration_shared_secret: "${registration_shared_key}"
report_stats: false
require_auth_for_profile_requests: true
room_list_publication_rules:
  - action: allow
    alias: '*'
    room_id: '*'
    user_id: '*'
send_federation: true
server_name: ${matrix_server_name}
signing_key_path: "/data/homeserver.signing.key"
spam_checker: []
start_pushers: true
suppress_key_server_warning: true
trusted_key_servers: []
url_preview_enabled: false
user_ips_max_age: 28d
EOF

    cat > "${lc}" <<'EOF'
version: 1
formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s'
handlers:
  file:
    class: logging.handlers.TimedRotatingFileHandler
    formatter: precise
    filename: /dev/null
    when: midnight
    backupCount: 3
    encoding: utf8
root:
  level: INFO
  handlers: [file]
disable_existing_loggers: false
EOF

    ${SUDO:-} docker run --rm -v matrix_synapse:/data -v "${tdir}":/src:ro alpine:latest \
        sh -c 'set -e; cp /src/homeserver.yaml /data/; cp /src/*.log.config /data/; mkdir -p /data/media; chown -R 991:991 /data; chmod -R 0770 /data'
    rm -rf "${tdir}"
    info "Synapse config seeded"
}
write_runtime_compose() {
    tmp_compose="${runtime_dir}/docker-compose.yaml"
    cat > "$tmp_compose" <<'YAML'
services:
  postgres:
    image: postgres:18-alpine
    container_name: matrix_postgres
    restart: unless-stopped
    logging: { driver: none }
    environment:
      - POSTGRES_DB=${postgres_db}
      - POSTGRES_USER=${postgres_user}
      - POSTGRES_PASSWORD=${postgres_password}
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=C --lc-ctype=C
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "${postgres_user}", "-d", "${postgres_db}"]
      interval: 5s
      timeout: 3s
      retries: 30
    volumes:
      - matrix_postgres:/var/lib/postgresql
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_postgres_ipv4}

  redis:
    image: redis:8-alpine
    container_name: matrix_redis
    restart: unless-stopped
    logging: { driver: none }
    mem_limit: "512m"
    mem_swappiness: 0
    security_opt:
      - no-new-privileges:true
    command:
      - redis-server
      - --save ""
      - --appendonly no
      - --dir /data
      - --maxmemory 256mb
      - --maxmemory-policy allkeys-lru
      - --loglevel warning
    volumes:
      - type: volume
        source: matrix_redis
        target: /data
        volume: { nocopy: true }
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 2s
      retries: 30
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_redis_ipv4}

  synapse:
    image: matrixdotorg/synapse:latest
    container_name: matrix_synapse
    user: "991:991"
    restart: unless-stopped
    logging: { driver: none }
    environment:
      - SYNAPSE_CONFIG_PATH=/data/homeserver.yaml
      - SYNAPSE_REPORT_STATS=no
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8008/health"]
      interval: 5s
      timeout: 3s
      retries: 60
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - matrix_synapse:/data
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_synapse_ipv4}
      matrix_external:
        ipv4_address: ${docker_external_synapse_ipv4}

networks:
  matrix_internal:
    name: matrix_internal
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${docker_internal_subnet_ipv4}
          gateway: ${docker_internal_gw_ipv4}
  matrix_external:
    name: matrix_external
    driver: bridge
    ipam:
      config:
        - subnet: ${docker_external_subnet_ipv4}
          gateway: ${docker_external_gw_ipv4}

volumes:
  matrix_postgres:
    external: true
  matrix_synapse:
    external: true
  matrix_redis:
    name: matrix_redis
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=256m,mode=0700,noexec,nosuid,nodev
YAML
}
pull_runtime_images() {
    ${SUDO:-} docker pull postgres:18-alpine >/dev/null
    ${SUDO:-} docker pull redis:8-alpine >/dev/null
    ${SUDO:-} docker pull matrixdotorg/synapse:latest >/dev/null
    ${SUDO:-} docker pull alpine:latest >/dev/null
}
compose_up() {
    info "docker compose up -d"
    tmp_env="${runtime_dir}/.env"

    cat >"$tmp_env" <<EOF
postgres_db=${postgres_db}
postgres_user=${postgres_user}
postgres_password=${postgres_password_runtime}
matrix_http_port=${matrix_http_port}
docker_internal_subnet_ipv4="$docker_internal_subnet_ipv4"
docker_external_subnet_ipv4="$docker_external_subnet_ipv4"
docker_internal_gw_ipv4="$docker_internal_gw_ipv4"
docker_internal_postgres_ipv4="$docker_internal_postgres_ipv4"
docker_internal_redis_ipv4="$docker_internal_redis_ipv4"
docker_internal_synapse_ipv4="$docker_internal_synapse_ipv4"
docker_internal_tunnel_ipv4="$docker_internal_tunnel_ipv4"
docker_external_gw_ipv4="$docker_external_gw_ipv4"
docker_external_synapse_ipv4="$docker_external_synapse_ipv4"
docker_external_tunnel_ipv4="$docker_external_tunnel_ipv4"
EOF

    __compose --env-file "$tmp_env" -f "$tmp_compose" -p matrix up -d --pull missing
    compose_up_flag=1
}
compose_down() {
    info "docker compose down"
    __compose --env-file "${tmp_env}" -f "${tmp_compose}" -p matrix down || true
    compose_up_flag=0
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
wait_synapse() {
    info "Waiting for Postgres health"
    if ! wait_health matrix_postgres 120; then
        err "Postgres did not become healthy. Health log:"
        print_health_log matrix_postgres
        die "Startup failed"
    fi

    info "Waiting for Synapse health"
    if ! wait_health matrix_synapse 180; then
        err "Synapse did not become healthy. Health log:"
        print_health_log matrix_synapse
        die "Startup failed"
    fi

    info "Synapse is healthy"
}
syn_curl() {
    ${SUDO:-} docker exec matrix_synapse curl -sS "$@"
}
wait_client_ready() {
    local i body
    for ((i=1;i<=180;i++)); do
        if body="$(syn_curl -m 5 http://127.0.0.1:8008/_matrix/client/versions 2>/dev/null)"; then
            if [[ "$(jq -r '.versions|type' <<<"${body}" 2>/dev/null)" = "array" ]]; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}
get_admin_token() {
    local attempts=10 sleep_s=2 http body token payload
    payload="$(jq -cn --arg u "@${matrix_admin}:${matrix_server_name}" --arg p "${matrix_password_admin}" '{type:"m.login.password", identifier:{type:"m.id.user", user:$u}, password:$p, device_id:"bootstrap", initial_device_display_name:"bootstrap"}')"

    local i
    for ((i=1;i<=attempts;i++)); do
        body="$(syn_curl -m 7 -H 'Content-Type: application/json' -d "${payload}" -w $'\n%{http_code}' http://127.0.0.1:8008/_matrix/client/v3/login || true)"
        http="${body##*$'\n'}"
        body="${body%$'\n'*}"
        token="$(jq -r '.access_token // empty' <<<"${body}" 2>/dev/null || true)"
        if [[ "${http}" = "200" && -n "${token}" ]]; then
            printf '%s' "${token}"
            return 0
        fi

        if (( i == 1 )); then
            body="$(syn_curl -m 7 -H 'Content-Type: application/json' -d "{\"type\":\"m.login.password\",\"user\":\"${matrix_admin}\",\"password\":\"${matrix_password_admin}\"}" -w $'\n%{http_code}' http://127.0.0.1:8008/_matrix/client/v3/login || true)"
            http="${body##*$'\n'}"; body="${body%$'\n'*}"
            token="$(jq -r '.access_token // empty' <<<"${body}" 2>/dev/null || true)"
            if [[ "${http}" = "200" && -n "${token}" ]]; then
                printf '%s' "${token}"
                return 0
            fi
        fi

        err "login attempt ${i}/${attempts} failed (http=${http}); $(jq -rc '{errcode,error} // empty' <<<\"${body}\" 2>/dev/null)"
        sleep "${sleep_s}"
        (( sleep_s < 8 )) && sleep_s=$((sleep_s*2))
    done
    return 1
}
create_matrix_users() {
    clear_scr
    echo "Starting user creation process..."
    local syn_id; syn_id="$(${SUDO:-} docker ps --filter 'name=matrix_synapse' --format '{{.ID}}')"
    local matrix_admin="$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 9 || true)"
    local matrix_password_admin="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 25 || true)"
    
    local i u pass
    for ((i=0;i<${#matrix_users_array[@]};i++)); do
        u="${matrix_users_array[$i]}"
        pass="${matrix_passwords_array[$i]}"
        [[ -z "$pass" ]] && die "Empty password for user $u"
        ${SUDO:-} docker exec "$syn_id" register_new_matrix_user -c /data/homeserver.yaml -u "$u" -p "$pass" --no-admin http://127.0.0.1:8008 >/dev/null 2>&1 || { echo "Failed user $u"; exit 1; }
        sleep 1
    done

    ${SUDO:-} docker exec "$syn_id" register_new_matrix_user -c /data/homeserver.yaml -u "$matrix_admin" -p "$matrix_password_admin" --admin http://127.0.0.1:8008 >/dev/null 2>&1 || { echo "Failed admin"; exit 1; }

    info "Waiting client API…"
    if ! wait_client_ready; then
        err "client API not ready after timeout"
        die "Startup failed"
    fi

    info "Logging in as admin…"
    local access_token
    access_token="$(get_admin_token || true)"
    [[ -n "${access_token}" ]] || { err "Failed to get admin token"; ${SUDO:-} docker logs --tail 200 matrix_synapse 1>&2 || true; die "Failed to get admin token"; }

    local dname u_now i2 body_dn
    for ((i2=0;i2<${#display_names_array[@]};i2++)); do
        u_now="${matrix_users_array[$i2]}"; dname="${display_names_array[$i2]}"
        body_dn="$(jq -nc --arg d "$dname" '{displayname:$d}')"
        syn_curl -X PUT -H "Authorization: Bearer ${access_token}" -H 'Content-Type: application/json' -d "${body_dn}" "http://127.0.0.1:8008/_synapse/admin/v2/users/@${u_now}:${matrix_server_name}" >/dev/null 2>&1 || { echo "Failed display name for $u_now"; exit 1; }
        sleep 1
    done

    local create_json room_id body_room
    body_room="$(jq -nc --arg a "${room_name}" --arg n "${room_name}" '{room_alias_name:$a, name:$n}')"
    create_json="$(syn_curl -X POST -H "Authorization: Bearer ${access_token}" -H 'Content-Type: application/json' -d "${body_room}" "http://127.0.0.1:8008/_matrix/client/v3/createRoom")"
    room_id="$(jq -r '.room_id // empty' <<<"$create_json")"
    [[ -n "$room_id" ]] || die "Failed to create room"

    local idx u2 body_inv
    for ((idx=0; idx<invite_count && idx<${#matrix_users_array[@]}; idx++)); do
        u2="${matrix_users_array[$idx]}"
        body_inv="$(jq -nc --arg uid "@${u2}:${matrix_server_name}" '{user_id:$uid}')"
        syn_curl -X POST -H "Authorization: Bearer ${access_token}" -H 'Content-Type: application/json' -d "${body_inv}" "http://127.0.0.1:8008/_matrix/client/v3/rooms/${room_id}/invite" >/dev/null 2>&1 || { echo "Failed invite $u2"; exit 1; }
        sleep 1
    done
}
make_package() {
    local pkg_root="$(mktemp -d "${tmp_folder}/matrix-pkg.XXXXXXXX")"
    append_tmp_dir "$pkg_root"
    local tmp="$(mktemp -d "${tmp_folder}/matrix-vols.XXXXXXXX")"
    append_tmp_dir "$tmp"
    local outdir="${pkg_root}/data"
    mkdir -p "$outdir"

    ${SUDO:-} docker run --rm --mount source=matrix_synapse,target=/syn -v "$tmp":/out alpine:latest sh -c "apk add --no-cache xz >/dev/null 2>&1 && tar -cJf /out/synapse.tar.xz -C /syn ."
    ${SUDO:-} docker run --rm --mount source=matrix_postgres,target=/pg -v "$tmp":/out alpine:latest sh -c "apk add --no-cache xz >/dev/null 2>&1 && tar -cJf /out/postgres.tar.xz -C /pg ."
    ${SUDO:-} docker run --rm --mount source=matrix_tunnel,target=/ssh -v "$tmp":/out alpine:latest sh -c "apk add --no-cache xz >/dev/null 2>&1 && tar -cJf /out/tunnel.tar.xz -C /ssh ."

    b64_oneline() {
        local f="$1"
        if command -v openssl >/dev/null 2>&1; then
            openssl base64 -A -in "$f"
        else
            base64 "$f" | tr -d '\n'
        fi
    }

    {
        printf 'volume_synapse="'; b64_oneline "$tmp/synapse.tar.xz"; printf '"\n'
        printf 'volume_postgres="'; b64_oneline "$tmp/postgres.tar.xz"; printf '"\n'
        printf 'volume_tunnel="'; b64_oneline "$tmp/tunnel.tar.xz"; printf '"\n'
    } > "$outdir/.volumes"

    chmod 600 "$outdir/.volumes"

    cat > "$outdir/.env" <<EOF
postgres_db=${postgres_db}
postgres_user=${postgres_user}
docker_internal_subnet_ipv4="$docker_internal_subnet_ipv4"
docker_external_subnet_ipv4="$docker_external_subnet_ipv4"
docker_internal_gw_ipv4="$docker_internal_gw_ipv4"
docker_internal_postgres_ipv4="$docker_internal_postgres_ipv4"
docker_internal_redis_ipv4="$docker_internal_redis_ipv4"
docker_internal_synapse_ipv4="$docker_internal_synapse_ipv4"
docker_internal_tunnel_ipv4="$docker_internal_tunnel_ipv4"
docker_external_gw_ipv4="$docker_external_gw_ipv4"
docker_external_synapse_ipv4="$docker_external_synapse_ipv4"
docker_external_tunnel_ipv4="$docker_external_tunnel_ipv4"
EOF

    mkdir -p "$outdir/tunnel"
    cat > "$outdir/tunnel/Dockerfile" <<'EOF'
FROM debian:trixie-slim

ARG docker_internal_synapse_ipv4
ENV docker_internal_synapse_ipv4="${docker_internal_synapse_ipv4}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates apt-transport-https && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt upgrade -y && \
    apt-get install -y --no-install-recommends openssh-client netcat-openbsd curl bash tzdata && \
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

wait_synapse() {
    while ! curl -fsS --max-time 3 http://${docker_internal_synapse_ipv4}:8008/health >/dev/null 2>&1; do
        sleep 1
    done
}

rmap="127.0.0.1:8008"
lmap="${docker_internal_synapse_ipv4}:8008"
backoff=3
backoff_max=30
trap 'exit 0' INT TERM

while true; do
    wait_synapse
    if ssh -q -F /ssh/config -o BatchMode=yes -o ConnectTimeout=5 -O check proxy; then
        ssh -q -F /ssh/config -O cancel -R "${rmap}" proxy >/dev/null 2>&1 || true
        ssh -q -F /ssh/config -O forward -R "${rmap}:${lmap}" proxy >/dev/null 2>&1 || true
        backoff=3
        sleep 5
        continue
    fi

    ssh -F /ssh/config -MNf proxy || true
    ssh -q -F /ssh/config -o BatchMode=yes -o ConnectTimeout=5 -O cancel -R "${rmap}" proxy >/dev/null 2>&1 || true
    ssh -q -F /ssh/config -o BatchMode=yes -o ConnectTimeout=5 -O forward -R "${rmap}:${lmap}" proxy >/dev/null 2>&1 || true

    sleep "${backoff}"
    if [[ "${backoff}" -lt "${backoff_max}" ]]; then
        backoff=$(( backoff * 2 ))
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
name: matrix
services:
  postgres:
    image: postgres:18-alpine
    container_name: matrix_postgres
    runtime: runsc
    restart: unless-stopped
    logging: { driver: none }
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "${postgres_user}", "-d", "${postgres_db}"]
      interval: 5s
      timeout: 3s
      retries: 30
    volumes:
      - matrix_postgres:/var/lib/postgresql
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_postgres_ipv4}
    security_opt:
      - apparmor:docker-matrix-postgres
      - seccomp=/etc/docker/seccomp-matrix.json

  redis:
    image: redis:8-alpine
    container_name: matrix_redis
    runtime: runsc
    restart: unless-stopped
    logging: { driver: none }
    mem_limit: "512m"
    mem_swappiness: 0
    command:
      - redis-server
      - --save ""
      - --appendonly no
      - --dir /data
      - --maxmemory 256mb
      - --maxmemory-policy allkeys-lru
      - --loglevel warning
    volumes:
      - type: volume
        source: matrix_redis
        target: /data
        volume:
          nocopy: true
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 3s
      timeout: 2s
      retries: 30
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_redis_ipv4}
    security_opt:
      - apparmor:docker-matrix-redis
      - seccomp=/etc/docker/seccomp-matrix.json
      - no-new-privileges:true

  synapse:
    image: matrixdotorg/synapse:latest
    container_name: matrix_synapse
    runtime: runc
    user: "991:991"
    restart: unless-stopped
    logging: { driver: none }
    environment:
      - SYNAPSE_CONFIG_PATH=/data/homeserver.yaml
      - SYNAPSE_REPORT_STATS=no
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8008/health"]
      interval: 5s
      timeout: 3s
      retries: 60
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }
    volumes:
      - matrix_synapse:/data
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_synapse_ipv4}
      matrix_external:
        ipv4_address: ${docker_external_synapse_ipv4}
    security_opt:
      - apparmor:docker-matrix-synapse
      - seccomp=/etc/docker/seccomp-matrix.json

  tunnel:
    build:
      context: ./tunnel
      args:
        docker_internal_synapse_ipv4: "${docker_internal_synapse_ipv4}"
    image: tunnel:latest
    pull_policy: never
    container_name: matrix_tunnel
    runtime: runsc
    restart: always
    logging: { driver: none }
    depends_on:
      synapse: { condition: service_healthy }
    volumes:
      - matrix_tunnel:/ssh:ro
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
    healthcheck:
      test: ["CMD", "ssh", "-q", "-F", "/ssh/config", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-O", "check", "proxy"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 30s
    networks:
      matrix_internal:
        ipv4_address: ${docker_internal_tunnel_ipv4}
      matrix_external:
        ipv4_address: ${docker_external_tunnel_ipv4}
    security_opt:
      - apparmor:docker-matrix-tunnel
      - seccomp=/etc/docker/seccomp-matrix.json

networks:
  matrix_internal:
    name: matrix_internal
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${docker_internal_subnet_ipv4}
          gateway: ${docker_internal_gw_ipv4}
  matrix_external:
    name: matrix_external
    driver: bridge
    ipam:
      config:
        - subnet: ${docker_external_subnet_ipv4}
          gateway: ${docker_external_gw_ipv4}

volumes:
  matrix_postgres:
    external: true
  matrix_synapse:
    external: true
  matrix_tunnel:
    external: true
  matrix_redis:
    name: matrix_redis
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=256m,mode=0700,noexec,nosuid,nodev
YAML

    mkdir -p "$final_out_dir"
    tar -C "$pkg_root" -cJf "$final_tar_path" data
}
preflight_cleanup() {
    info "Pre-flight cleanup (containers/volumes/networks)"
    ${SUDO:-} docker ps -aq -f "name=^matrix_(synapse|postgres|redis|tunnel)$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^matrix_(synapse|postgres|tunnel|redis)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^matrix_(external|internal)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    prune_build_caches
}
final_cleanup() {
    info "Final cleanup (containers/volumes/networks)"
    ${SUDO:-} docker ps -aq -f "name=^matrix_(synapse|postgres|redis|tunnel)$" | xargs $xargs_r ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "name=^matrix_(synapse|postgres|tunnel|redis)$" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "name=^matrix_(external|internal)$" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=matrix" | xargs $xargs_r ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    cleanup_images
}
main() {
    check_pkg
    preflight_cleanup
    clear_scr
    prompt_users_mode_and_token
    users_mode="${USERS_MODE}"
    users_token="${USERS_TOKEN:-}"
    clear_scr
    local deploy_env
    deploy_env="$(prompt_deploy_token)" || die "Failed to decode Deploy Token"
    eval "$deploy_env"

    if [[ "${users_mode}" == "restore" ]]; then
        [[ -n "${users_token}" ]] && export USERS_TOKEN="${users_token}"
        info "Using users from Users Token (restore mode)"
        decode_users_token_via_docker "${users_token:?}"
    else
        local matrix_env
        matrix_env="$(prompt_matrix_config)" || die "Failed to get Matrix configuration"
        eval "$matrix_env"
        clear_scr
        info "Generating usernames / display names / passwords…"
        generate_users_data
        clear_scr
    fi

    (( invite_count > ${#matrix_users_array[@]} )) && invite_count="${#matrix_users_array[@]}"

    if [[ "${users_mode:-}" != "restore" ]]; then
        users_token="$(make_users_token_via_docker || true)"
    fi

    docker_internal_subnet_ipv4='172.27.0.0/24'
    docker_external_subnet_ipv4='172.28.0.0/24'
    int_pref="${docker_internal_subnet_ipv4%/*}"
    ext_pref="${docker_external_subnet_ipv4%/*}"
    int_pref="${int_pref%.*}."
    ext_pref="${ext_pref%.*}."
    docker_internal_gw_ipv4="${int_pref}1"
    docker_internal_postgres_ipv4="${int_pref}2"
    docker_internal_redis_ipv4="${int_pref}3"
    docker_internal_synapse_ipv4="${int_pref}4"
    docker_internal_tunnel_ipv4="${int_pref}5"
    docker_external_gw_ipv4="${ext_pref}1"
    docker_external_synapse_ipv4="${ext_pref}4"
    docker_external_tunnel_ipv4="${ext_pref}5"

    create_volumes
    seed_tunnel_volume
    seed_synapse_config
    pull_runtime_images
    write_runtime_compose
    start_session_guard "matrix" "$tmp_compose"
    compose_up
    wait_synapse
    create_matrix_users
    compose_down
    make_package
    final_cleanup
    clear_scr

    printf "%-20s %-26s %-30s\n\n" "Username:" "Display Name:" "Password:"
    local i
    for ((i=0;i<${#matrix_users_array[@]};i++)); do
        printf "%-20s %-26s %-30s\n" "${matrix_users_array[$i]}" "${display_names_array[$i]}" "${matrix_passwords_array[$i]}"
    done

    if [[ -n "${users_token:-}" ]]; then
        echo
        echo "Restore Users Token:"
        echo "${users_token}"
        echo
    fi

    info "Package created: ${final_tar_path}"
}

if [[ "${BASH_SOURCE[0]-$0}" == "$0" ]]; then
    main "$@"
fi
