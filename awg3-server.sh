#!/bin/sh
#
# awg3-server: an AmneziaWG 3.1 server in its own container.
#
# Runs on the server as root, fed over ssh:
#   ssh HOST 'sh -s -- install [port]' < awg3-server.sh
#   ssh HOST 'sh -s -- add-peer [-d DNS] [-a ADDR] <name> <public-key>' < awg3-server.sh > peer.conf
#   ssh HOST 'sh -s -- status' < awg3-server.sh
#   ssh HOST 'sh -s -- uninstall' < awg3-server.sh
#
# Same image family and layout as the AmneziaVPN client's awg container:
# awg-quick inside, NAT out of eth0. Differences: the config lives on a host
# directory, so recreating the container keeps the keys; the peer's private
# key never reaches the server; obfuscation parameters are drawn per server
# instead of the client's shared defaults.
#
# Several servers on one host: AWG_NAME, AWG_DIR, AWG_SUBNET and AWG_IMAGE
# override the defaults below, so the same script installs and serves each
# of them. Give every server its own name, directory and subnet.
#
# The AmneziaVPN client app recognises a server by the container name and
# the files it keeps beside the config, so those are written here too:
# the client table and the server key files. An app-made container can be
# replaced by this script - keep its name and image, and the app goes on
# seeing the server, now with its config on the host instead of inside a
# container layer that every update discards.
#
# add-peer prints the peer's config without PrivateKey. It still carries
# the preshared and header protection keys: redirect it to a file with
# restricted permissions, never to a terminal or a log.
#

set -eu

IMAGE="${AWG_IMAGE:-amneziavpn/amneziawg-go:3.1.20260828}"
NAME="${AWG_NAME:-awg3}"
DIR="${AWG_DIR:-/opt/awg3}"
CONF="$DIR/awg0.conf"
PORT_FILE="$DIR/port"
IN_CONTAINER="/opt/amnezia/awg"

# What the client app expects to find next to the config.
TABLE="$DIR/clientsTable"
KEY_PRIV="$DIR/wireguard_server_private_key.key"
KEY_PUB="$DIR/wireguard_server_public_key.key"
KEY_PSK="$DIR/wireguard_psk.key"

SUBNET="${AWG_SUBNET:-10.8.3}"
SERVER_ADDR="$SUBNET.1"
PORT_MIN=30000
PORT_MAX=60999

# A small server without swap may already be carrying another tunnel;
# refuse to start a second one when memory is short.
MEM_MIN_KB=61440

# Client MTU as the AmneziaVPN client uses on macOS (Network Extension)
# and mobile. With S4 up to 64 a data packet stays under 1404 bytes.
CLIENT_MTU=1280

# I1 imitates a DNS answer for one of these names, picked per peer. Set
# them to sites that are popular where the peers connect from: a name no
# one there resolves is itself a signature.
DNS_NAMES="wikipedia.org github.com cloudflare.com apple.com microsoft.com amazon.com netflix.com spotify.com reddit.com wordpress.org"

die() {
    echo "awg3-server: $*" >&2
    exit 1
}

# Random integer in [lo, hi].
rnd() {
    echo $(( $1 + $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % ($2 - $1 + 1) ))
}

# Random "lo-hi" range: lo in [lo_min, lo_max], hi = lo + [add_min, add_max].
rnd_range() {
    local lo

    lo=$(rnd "$1" "$2")
    echo "$lo-$(( lo + $(rnd "$3" "$4") ))"
}

pick_word() {
    set -- $1
    shift "$(rnd 0 $(( $# - 1 )))"
    echo "$1"
}

container_exists() {
    # "docker inspect" answers for an image of the same name too, and an
    # app-made server has exactly that: image and container share a name.
    docker container inspect "$NAME" >/dev/null 2>&1
}

port_in_use() {
    ss -Hlun | awk '{print $4}' | grep -qE "[:.]$1\$"
}

pick_port() {
    local p tries=0

    while [ "$tries" -lt 50 ]; do
        p=$(rnd "$PORT_MIN" "$PORT_MAX")
        port_in_use "$p" || { echo "$p"; return 0; }
        tries=$(( tries + 1 ))
    done
    return 1
}

genkey() {
    docker run --rm --entrypoint awg "$IMAGE" genkey
}

pubkey() {
    printf '%s' "$1" | docker run -i --rm --entrypoint awg "$IMAGE" pubkey
}

genpsk() {
    docker run --rm --entrypoint awg "$IMAGE" genpsk
}

#
# The client table the app reads: one entry per peer, appended in the
# app's own layout. Written by this script from the first install on, so
# the closing bracket is always the last line.
#
table_add() {
    local pub="$1" name="$2" addr="$3" tmp="$TABLE.new"

    if grep -q '"clientId"' "$TABLE" 2>/dev/null; then
        sed '$d' "$TABLE" | sed '$ s/^\( *\)}$/\1},/' >"$tmp"
    else
        echo "[" >"$tmp"
    fi

    cat >>"$tmp" <<EOF
    {
        "clientId": "$pub",
        "userData": {
            "allowed_ips": "$addr",
            "clientName": "$name",
            "creationDate": "$(date '+%a %b %e %H:%M:%S %Y')"
        }
    }
]
EOF
    mv "$tmp" "$TABLE"
}

#
# Four distinct message types. Single values, not ranges: with
# RandomTrailers a range claims data packets in proportion to its width
# (amneziawg-go #186). Below 2^31 for clients that read them as int32.
# Header protection encrypts them on the wire anyway.
#
gen_headers() {
    local h all=" "

    while [ "$(echo $all | wc -w)" -lt 4 ]; do
        h=$(rnd 5 2147483647)
        case "$all" in *" $h "*) continue ;; esac
        all="$all$h "
    done
    echo $all
}

#
# A DNS answer: random id, flags 0x8180, one question and one A record;
# TTL and address are random bytes in every packet. Shaped like a known
# protocol rather than random bytes, and not the icloud.com packet that
# every AmneziaVPN install sends (amnezia-client #2857).
#
gen_i1() {
    local name label qname=""

    name=$(pick_word "$DNS_NAMES")
    for label in $(echo "$name" | tr . ' '); do
        qname="$qname$(printf '%02x' ${#label})$(printf '%s' "$label" | od -An -tx1 | tr -d ' \n')"
    done
    echo "<r 2><b 0x81800001000100000000${qname}0000010001c00c00010001><r 4><b 0x0004><r 4>"
}

write_start_script() {
    cat >"$DIR/start.sh" <<'EOF'
#!/bin/sh
# Container entrypoint: bring awg0 up and forward the tunnel out of eth0.
conf=/opt/amnezia/awg/awg0.conf
awg-quick down "$conf" 2>/dev/null
awg-quick up "$conf" || exit 1

subnet=$(sed -n 's/^Address *= *//p' "$conf")
add() { iptables -C "$@" 2>/dev/null || iptables -A "$@"; }
add INPUT -i awg0 -j ACCEPT
add FORWARD -i awg0 -o eth0 -s "$subnet" -j ACCEPT
add FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$subnet" -o eth0 -j MASQUERADE 2>/dev/null ||
    iptables -t nat -A POSTROUTING -s "$subnet" -o eth0 -j MASQUERADE
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null ||
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

exec tail -f /dev/null
EOF
    chmod 700 "$DIR/start.sh"
}

#
# Server-side parameters, drawn once per server.
#
# S1-S4 share one value: header protection needs each at least 12, the
# AmneziaVPN client caps S3 at 64, and unequal values lose data packets
# with RandomTrailers (amneziawg-go PR #183). RandomTrailers is on: with
# single H values and equal S its throughput matched the tunnel without it.
# Timer ranges are drawn around the AmneziaVPN defaults, keeping every
# RekeyAfterTime below every RejectAfterTime.
#
write_server_conf() {
    local port="$1" priv hpk s h1 h2 h3 h4 jmin

    # Generated before the heredoc: a failed substitution inside it would
    # not stop the script and would leave a config with an empty key.
    priv=$(genkey)
    hpk=$(genkey)
    [ ${#priv} -eq 44 ] && [ ${#hpk} -eq 44 ] || die "key generation failed"

    # The app looks for its key files beside the config; without them it
    # treats the server as not installed.
    printf '%s\n' "$priv" >"$KEY_PRIV"
    pubkey "$priv" >"$KEY_PUB"
    genpsk >"$KEY_PSK"
    printf '[\n]\n' >"$TABLE"

    s=$(rnd 12 64)
    set -- $(gen_headers)
    h1=$1 h2=$2 h3=$3 h4=$4
    jmin=$(rnd 40 89)

    cat >"$CONF" <<EOF
[Interface]
PrivateKey = $priv
Address = $SERVER_ADDR/24
ListenPort = $port
Jc = $(rnd 4 8)
Jmin = $jmin
Jmax = $(( jmin + $(rnd 50 250) ))
S1 = $s
S2 = $s
S3 = $s
S4 = $s
H1 = $h1
H2 = $h2
H3 = $h3
H4 = $h4
HeaderProtectionKey = $hpk
ContentPaddingAddition = $(rnd_range 8 24 40 96)
RekeyAfterTime = $(rnd_range 90 110 10 30)
RekeyTimeout = $(rnd_range 3 5 1 3)
RejectAfterTime = $(rnd_range 150 170 10 30)
KeepaliveTimeout = $(rnd_range 5 8 4 8)
MaxHandshakeAttempts = $(rnd_range 15 18 2 5)
RandomTrailers = on
DisableCookies = on
EOF
}

cmd_install() {
    local port avail

    container_exists && die "container $NAME already exists"

    avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    [ "$avail" -ge "$MEM_MIN_KB" ] ||
        die "MemAvailable ${avail} kB is below ${MEM_MIN_KB} kB; not starting"

    umask 077
    mkdir -p "$DIR"

    if [ -f "$CONF" ]; then
        port=$(cat "$PORT_FILE")
    else
        if [ -n "${1:-}" ]; then
            port="$1"
            port_in_use "$port" && die "udp port $port is in use"
        else
            port=$(pick_port) || die "no free udp port found"
        fi
        # An image built on the host - the app builds its own - has nothing
        # to be pulled from.
        docker image inspect "$IMAGE" >/dev/null 2>&1 ||
            docker pull -q "$IMAGE" >/dev/null
        write_server_conf "$port"
        echo "$port" >"$PORT_FILE"
    fi

    write_start_script

    docker run -d \
        --name "$NAME" \
        --restart always \
        --log-driver none \
        --privileged \
        --cap-add NET_ADMIN \
        --cap-add SYS_MODULE \
        --sysctl net.ipv4.conf.all.src_valid_mark=1 \
        --sysctl net.ipv4.ip_forward=1 \
        -p "$port:$port/udp" \
        -v "$DIR:$IN_CONTAINER" \
        --entrypoint /bin/sh \
        "$IMAGE" "$IN_CONTAINER/start.sh" >/dev/null

    sleep 3
    docker exec "$NAME" awg show awg0 listen-port >/dev/null ||
        die "awg0 did not come up; see: docker logs $NAME"

    echo "installed: container $NAME, udp $port"
}

server_public_ip() {
    ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'
}

next_peer_addr() {
    local last

    last=$(sed -n "s|^AllowedIPs = $SUBNET\.\([0-9]*\)/32|\1|p" "$CONF" | sort -n | tail -1)
    last=${last:-1}
    [ "$last" -lt 254 ] || return 1
    echo "$SUBNET.$(( last + 1 ))"
}

conf_value() {
    sed -n "s/^$1 = //p" "$CONF" | head -1
}

cmd_add_peer() {
    local name pub addr psk key i1 dns="" want=""

    while [ $# -gt 0 ]; do
        case "$1" in
            -d) dns="${2:-}"; [ -n "$dns" ] || die "-d needs a resolver"; shift 2 ;;
            -a) want="${2:-}"; [ -n "$want" ] || die "-a needs an address"; shift 2 ;;
            *) break ;;
        esac
    done

    name="${1:-}" pub="${2:-}"
    [ -n "$name" ] && [ -n "$pub" ] || die "usage: add-peer [-d DNS] [-a ADDR] <name> <public-key>"
    printf '%s' "$pub" | grep -qE '^[A-Za-z0-9+/]{43}=$' || die "not a public key: $pub"
    container_exists || die "container $NAME is not installed"
    grep -qF "PublicKey = $pub" "$CONF" && die "peer with this key already exists"

    if [ -n "$want" ]; then
        # An address asked for by hand: a numbering scheme of one's own
        # outlives the order peers happened to be added in.
        case "$want" in
            "$SUBNET".*) ;;
            *) die "address $want is outside $SUBNET.0/24" ;;
        esac
        grep -qF "AllowedIPs = $want/32" "$CONF" && die "address $want is taken"
        addr="$want"
    else
        addr=$(next_peer_addr) || die "subnet $SUBNET.0/24 is full"
    fi
    psk=$(docker exec "$NAME" awg genpsk)
    i1=$(gen_i1)

    # I1 is the peer's alone and the server never sends it, but a peer that
    # has to be issued again should get the packet it already had: kept as
    # a comment, which awg-quick strips along with the rest.
    umask 077
    cat >>"$CONF" <<EOF

[Peer]
# $name
# I1 = $i1
PublicKey = $pub
PresharedKey = $psk
AllowedIPs = $addr/32
EOF

    # No process substitution: the app's own image is not guaranteed to
    # have a shell that provides it.
    docker exec "$NAME" sh -c \
        "awg-quick strip $IN_CONTAINER/awg0.conf > /tmp/awg0.stripped && \
         awg syncconf awg0 /tmp/awg0.stripped && \
         rm -f /tmp/awg0.stripped && \
         ip route replace $addr/32 dev awg0"

    table_add "$pub" "$name" "$addr/32"

    # Client side: junk and I1 matter only on the sending side, timers and
    # the rest must match what the server was drawn with.
    echo "[Interface]"
    echo "Address = $addr/32"
    echo "MTU = $CLIENT_MTU"
    if [ -n "$dns" ]; then
        echo "DNS = $dns"
    fi
    for key in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
        echo "$key = $(conf_value $key)"
    done
    echo "I1 = $i1"
    for key in HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout \
        RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies; do
        echo "$key = $(conf_value $key)"
    done
    cat <<EOF

[Peer]
PublicKey = $(docker exec "$NAME" awg show awg0 public-key)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0
Endpoint = $(server_public_ip):$(cat "$PORT_FILE")
PersistentKeepalive = $(rnd_range 20 28 5 10)
EOF
}

cmd_status() {
    if ! container_exists; then
        echo "container $NAME: not installed"
        return 0
    fi
    docker ps -a --filter "name=^${NAME}\$" --format 'container {{.Names}}: {{.Status}}, {{.Ports}}'
    # awg show hides private and preshared keys but prints the header
    # protection key, which is as secret as they are.
    if docker exec "$NAME" awg show awg0 >/dev/null 2>&1; then
        docker exec "$NAME" awg show awg0 |
            sed -E 's/^( *header protection key): .*/\1: (hidden)/'
    else
        echo "awg0: down"
    fi
    # Peer names only: the I1 kept beside each of them is a comment too.
    grep '^# ' "$CONF" | grep -v '^# I1 = ' | sed 's/^# /peer name: /' || true
}

cmd_uninstall() {
    container_exists || { echo "container $NAME: not installed"; return 0; }
    docker rm -f "$NAME" >/dev/null
    echo "removed container $NAME; keys and config kept in $DIR"
}

case "${1:-}" in
    install) shift; cmd_install "$@" ;;
    add-peer) shift; cmd_add_peer "$@" ;;
    status) cmd_status ;;
    uninstall) cmd_uninstall ;;
    *) die "usage: install [port] | add-peer [-d DNS] [-a ADDR] <name> <public-key> | status | uninstall" ;;
esac
