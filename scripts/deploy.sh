#!/bin/sh
set -eu

ready_attempts=${HYDRAT_READY_ATTEMPTS:-360}
ready_consecutive=${HYDRAT_READY_CONSECUTIVE_SUCCESSES:-10}
ready_delay=${HYDRAT_READY_DELAY_SECONDS:-2}
ready_max_time=${HYDRAT_READY_MAX_TIME_SECONDS:-2}
compose_wait_timeout=${HYDRAT_COMPOSE_WAIT_TIMEOUT_SECONDS:-180}

for value in "$ready_attempts" "$ready_consecutive" "$ready_delay" "$ready_max_time" "$compose_wait_timeout"; do
  case "$value" in
    ''|*[!0-9]*)
      echo "deploy readiness settings must be non-negative integers" >&2
      exit 2
      ;;
  esac
done
if [ "$ready_attempts" -eq 0 ] || [ "$ready_consecutive" -eq 0 ] || [ "$ready_max_time" -eq 0 ] || [ "$compose_wait_timeout" -eq 0 ]; then
  echo "attempts, consecutive successes, curl max-time and compose wait timeout must be greater than zero" >&2
  exit 2
fi

docker compose up -d --no-build --force-recreate --wait \
  --wait-timeout "$compose_wait_timeout" gateway controller

attempt=1
consecutive=0
while [ "$attempt" -le "$ready_attempts" ]; do
  ready_body=''
  if ready_body=$(docker compose exec -T controller curl \
    --fail-with-body --silent --show-error --max-time "$ready_max_time" \
    http://127.0.0.1:8080/api/ready); then
    consecutive=$((consecutive + 1))
    if [ "$consecutive" -ge "$ready_consecutive" ]; then
      echo "Hydrat deployment is ready after $consecutive consecutive checks at attempt $attempt/$ready_attempts"
      exit 0
    fi
  else
    consecutive=0
    if [ -n "$ready_body" ]; then
      printf 'Hydrat readiness pending at attempt %s/%s: %s\n' \
        "$attempt" "$ready_attempts" "$ready_body" >&2
    else
      printf 'Hydrat readiness pending at attempt %s/%s: no response body\n' \
        "$attempt" "$ready_attempts" >&2
    fi
  fi
  if [ "$attempt" -lt "$ready_attempts" ] && [ "$ready_delay" -gt 0 ]; then
    sleep "$ready_delay"
  fi
  attempt=$((attempt + 1))
done

echo "Hydrat release rejected: controller /api/ready did not stay ready for $ready_consecutive consecutive checks" >&2
echo "Keep the recorded rollback image and pre-deployment backup; follow docs/operations.md" >&2
exit 1
