#!/bin/sh
set -eu

usage() {
	echo "usage: qoe-netem.sh apply|clear IFACE DESTINATION_IP DESTINATION_PORT" >&2
	exit 2
}

if [ "$#" -ne 4 ]; then
	usage
fi

action=$1
iface=$2
destination=$3
port=$4

case "$action" in
	apply | clear) ;;
	*)
		echo "action must be apply or clear" >&2
		exit 2
		;;
esac

if [ -z "$iface" ]; then
	echo "interface is required" >&2
	exit 2
fi

valid_ipv4() {
	value=$1
	case "$value" in
		.* | *. | *..*) return 1 ;;
	esac
	previous_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # Intentional IPv4 octet split with glob characters rejected above.
	set -- $value
	IFS=$previous_ifs
	[ "$#" -eq 4 ] || return 1
	for octet do
		case "$octet" in
			'' | *[!0-9]*) return 1 ;;
		esac
		[ "$octet" -le 255 ] || return 1
	done
}

if ! valid_ipv4 "$destination"; then
	echo "destination must be an IPv4 address" >&2
	exit 2
fi
case "$port" in
	'' | *[!0-9]*)
		echo "destination port must be between 1 and 65535" >&2
		exit 2
		;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
	echo "destination port must be between 1 and 65535" >&2
	exit 2
fi

if [ "$(uname -s)" != "Linux" ] || ! command -v tc >/dev/null 2>&1; then
	echo "Linux tc is required for qoe-netem shaping" >&2
	exit 77
fi

case "$action" in
	apply)
		cleanup_partial=false
		cleanup_on_exit() {
			if [ "$cleanup_partial" = true ]; then
				tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
			fi
		}
		trap cleanup_on_exit 0
		# Send every skb priority to the unshaped second band. Only the
		# endpoint-specific filter below may select shaped band 1:3.
		tc qdisc replace dev "$iface" root handle 1: prio bands 3 \
			priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
		cleanup_partial=true
		tc qdisc replace dev "$iface" parent 1:3 handle 30: netem delay 1800ms rate 192kbit
		tc filter replace dev "$iface" protocol ip parent 1: prio 30 u32 \
			match ip dst "$destination/32" \
			match ip protocol 6 0xff \
			match ip dport "$port" 0xffff \
			flowid 1:3 \
			action pass
		cleanup_partial=false
		trap - 0
		;;
	clear)
		tc qdisc del dev "$iface" root 2>/dev/null || true
		;;
esac
