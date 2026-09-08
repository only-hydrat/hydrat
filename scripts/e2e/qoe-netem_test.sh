#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
helper=$script_dir/qoe-netem.sh

if [ ! -f "$helper" ]; then
	echo "qoe-netem helper is missing: $helper" >&2
	exit 1
fi

expect_status() {
	want=$1
	shift
	set +e
	sh "$helper" "$@" >/dev/null 2>&1
	got=$?
	set -e
	if [ "$got" -ne "$want" ]; then
		echo "qoe-netem.sh $* exited $got, want $want" >&2
		exit 1
	fi
}

# Argument validation is host-independent and must remain strict even where tc
# cannot be used (for example, on a macOS development machine).
expect_status 2
expect_status 2 apply lo 192.0.2.10
expect_status 2 invalid lo 192.0.2.10 443
expect_status 2 apply '' 192.0.2.10 443
expect_status 2 apply lo not-an-ip 443
expect_status 2 apply lo 192.0.2.10. 443
expect_status 2 apply lo 192.0..10 443
expect_status 2 apply lo 192.0.2.10 0
expect_status 2 apply lo 192.0.2.10 443 extra

if [ "$(uname -s)" != "Linux" ] || ! command -v ip >/dev/null 2>&1 ||
	! command -v tc >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: Linux iproute2 and python3 are required for qoe-netem contract" >&2
	exit 77
fi

client_namespace=hydrat-qoe-client-$$
server_namespace=hydrat-qoe-server-$$
client_created=false
server_created=false
server_pid=
cleanup() {
	if [ -n "$server_pid" ]; then
		kill "$server_pid" >/dev/null 2>&1 || true
	fi
	if [ "$client_created" = true ]; then
		ip netns exec "$client_namespace" sh "$helper" clear qoe-client0 192.0.2.10 18443 >/dev/null 2>&1 || true
		ip netns del "$client_namespace" >/dev/null 2>&1 || true
	fi
	if [ "$server_created" = true ]; then
		ip netns del "$server_namespace" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if ! ip netns add "$client_namespace" >/dev/null 2>&1; then
	echo "SKIP: CAP_NET_ADMIN is required for qoe-netem contract" >&2
	exit 77
fi
client_created=true
if ! ip netns add "$server_namespace" >/dev/null 2>&1; then
	echo "SKIP: CAP_NET_ADMIN is required for a second qoe-netem namespace" >&2
	exit 77
fi
server_created=true
if ! ip link add qoe-client0 type veth peer name qoe-server0 >/dev/null 2>&1; then
	echo "SKIP: veth network interfaces are unavailable" >&2
	exit 77
fi
ip link set qoe-client0 netns "$client_namespace"
ip link set qoe-server0 netns "$server_namespace"
ip -n "$client_namespace" address add 192.0.2.1/24 dev qoe-client0
ip -n "$server_namespace" address add 192.0.2.10/24 dev qoe-server0
ip -n "$server_namespace" address add 192.0.2.20/24 dev qoe-server0
ip -n "$client_namespace" link set lo up
ip -n "$server_namespace" link set lo up
ip -n "$client_namespace" link set qoe-client0 up
ip -n "$server_namespace" link set qoe-server0 up

ip netns exec "$server_namespace" python3 -c '
import select
import socket
import time

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", 18443))
tcp.listen()
tcp.setblocking(False)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", 18443))
udp.setblocking(False)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    readable, _, _ = select.select([tcp, udp], [], [], 0.25)
    for current in readable:
        if current is tcp:
            connection, _ = tcp.accept()
            connection.recv(1)
            connection.close()
        else:
            current.recvfrom(1)
' &
server_pid=$!

send_packet() {
	kind=$1
	destination_ip=$2
	tos=$3
	ip netns exec "$client_namespace" python3 - "$kind" "$destination_ip" "$tos" <<'PY'
import socket
import sys

kind, destination, tos = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
socket_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
probe = socket.socket(socket.AF_INET, socket_type)
probe.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
probe.settimeout(8)
if kind == "tcp":
    probe.connect((destination, 18443))
    probe.sendall(b"x")
else:
    probe.sendto(b"x", (destination, 18443))
probe.close()
PY
}

# Wait for the disposable server without relying on a fixed startup sleep.
attempt=0
until send_packet tcp 192.0.2.20 0; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 40 ]; then
		echo "disposable qoe-netem server did not become ready" >&2
		exit 1
	fi
	sleep 0.05
done

netem_packets() {
	ip netns exec "$client_namespace" tc -s qdisc show dev qoe-client0 | awk '
		/qdisc netem 30:/ { netem = 1; next }
		netem && /Sent / {
			for (field = 1; field <= NF; field++) {
				if ($field == "pkt") { print $(field - 1); exit }
			}
		}
	'
}

filter_packets() {
	ip netns exec "$client_namespace" tc -s filter show dev qoe-client0 parent 1: | awk '
		/flowid 1:3/ { target = 1 }
		target && /Sent / {
			for (field = 1; field <= NF; field++) {
				if ($field == "pkt") { print $(field - 1); exit }
			}
		}
	'
}

require_number() {
	label=$1
	value=$2
	case "$value" in
		'' | *[!0-9]*)
			echo "$label is not a packet counter: $value" >&2
			exit 1
			;;
	esac
}

stable_counters() {
	previous_netem=-1
	previous_filter=-1
	stable=0
	attempt=0
	while [ "$attempt" -lt 120 ]; do
		current_netem=$(netem_packets)
		current_filter=$(filter_packets)
		require_number "stable netem count" "$current_netem"
		require_number "stable filter count" "$current_filter"
		if [ "$current_netem" -eq "$previous_netem" ] &&
			[ "$current_filter" -eq "$previous_filter" ]; then
			stable=$((stable + 1))
		else
			stable=0
		fi
		# The configured 1.8s delay can release later TCP control packets.
		# Require a margin beyond that delay before attributing a later delta
		# to the next test packet.
		if [ "$stable" -ge 25 ]; then
			echo "$current_netem $current_filter"
			return
		fi
		previous_netem=$current_netem
		previous_filter=$current_filter
		attempt=$((attempt + 1))
		sleep 0.1
	done
	echo "qoe-netem counters did not stabilize" >&2
	exit 1
}

ip netns exec "$client_namespace" sh "$helper" apply qoe-client0 192.0.2.10 18443

qdisc_output=$(ip netns exec "$client_namespace" tc qdisc show dev qoe-client0)
echo "$qdisc_output" | grep -q 'qdisc prio 1: root'
echo "$qdisc_output" | grep -q 'qdisc netem 30: parent 1:3'

filter_output=$(ip netns exec "$client_namespace" tc filter show dev qoe-client0 parent 1:)
echo "$filter_output" | grep -q 'flowid 1:3'
echo "$filter_output" | grep -Eiq 'c000020a|192\.0\.2\.10'
echo "$filter_output" | grep -Eiq '480b|dport 18443'
echo "$filter_output" | grep -Eiq '0006|protocol 6'

before=$(netem_packets)
require_number "initial netem count" "$before"
filter_before=$(filter_packets)
require_number "initial filter count" "$filter_before"
send_packet tcp 192.0.2.10 0
target_counts=$(stable_counters)
after_target=${target_counts% *}
filter_after_target=${target_counts#* }
if [ "$after_target" -le "$before" ]; then
	echo "target TCP packet did not traverse netem: before=$before after=$after_target" >&2
	exit 1
fi
if [ "$filter_after_target" -le "$filter_before" ]; then
	echo "target TCP packet did not increment filter: before=$filter_before after=$filter_after_target" >&2
	exit 1
fi

# The review reproduction used throughput TOS 0x08. It and the alternative
# endpoint must remain outside netem even though the target uses the same port.
send_packet tcp 192.0.2.20 0x08
alternative_counts=$(stable_counters)
after_alternative=${alternative_counts% *}
filter_after_alternative=${alternative_counts#* }
if [ "$after_alternative" -ne "$after_target" ]; then
	echo "alternative TCP packet leaked into netem: target=$after_target alternative=$after_alternative" >&2
	exit 1
fi
if [ "$filter_after_alternative" -ne "$filter_after_target" ]; then
	echo "alternative TCP packet matched target filter: target=$filter_after_target alternative=$filter_after_alternative" >&2
	exit 1
fi

# The helper contract is TCP-only; UDP to the selected endpoint stays direct.
send_packet udp 192.0.2.10 0
udp_counts=$(stable_counters)
after_udp=${udp_counts% *}
filter_after_udp=${udp_counts#* }
if [ "$after_udp" -ne "$after_alternative" ]; then
	echo "target UDP packet leaked into TCP-only netem: before=$after_alternative after=$after_udp" >&2
	exit 1
fi
if [ "$filter_after_udp" -ne "$filter_after_alternative" ]; then
	echo "target UDP packet matched TCP-only filter: before=$filter_after_alternative after=$filter_after_udp" >&2
	exit 1
fi

echo "$qdisc_output" | grep -q 'priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1'

ip netns exec "$client_namespace" sh "$helper" clear qoe-client0 192.0.2.10 18443
qdisc_output=$(ip netns exec "$client_namespace" tc qdisc show dev qoe-client0)
if echo "$qdisc_output" | grep -Eq 'qdisc (prio 1:|netem 30:)'; then
	echo "qoe-netem clear left a shaping qdisc: $qdisc_output" >&2
	exit 1
fi

# Clearing an already-clear interface must be safe for EXIT traps.
ip netns exec "$client_namespace" sh "$helper" clear qoe-client0 192.0.2.10 18443
echo "qoe-netem contract passed"
