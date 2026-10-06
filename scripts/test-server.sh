#!/usr/bin/env bash
# Disposable Stalwart mail server for kiskadee's integration and e2e tests.
#
# Starts a fresh container, completes Stalwart's setup headlessly over JMAP
# (x:Bootstrap/set, no browser wizard), and creates a test mailbox.
# Hostname is `localhost` so the JMAP session's absolute URLs
# (https://localhost/jmap/) resolve; the cert is self-signed, so only test
# clients may accept invalid certs.
#
# Usage: scripts/test-server.sh [up|down]
# Prints the credentials as KEY=value lines on success.
set -euo pipefail

NAME=kiskadee-stalwart
IMAGE=stalwartlabs/stalwart:latest
TEST_USER=alice
TEST_PASS=alice-test-pass
DOMAIN=localhost

jmap() { # jmap <user:pass> <url> <json>
  curl -sfk -u "$1" -H 'Content-Type: application/json' "$2" -d "$3"
}

down() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }

up() {
  down
  docker run -d --name "$NAME" \
    -p 127.0.0.1:443:443 -p 127.0.0.1:18080:8080 -p 127.0.0.1:10143:143 -p 127.0.0.1:10993:993 \
    "$IMAGE" >/dev/null

  local temp_pass=""
  for _ in $(seq 1 30); do
    temp_pass=$(docker logs "$NAME" 2>&1 | sed -n 's/.*password: \([A-Za-z0-9]*\).*/\1/p' | head -1)
    [ -n "$temp_pass" ] && curl -sf -o /dev/null http://127.0.0.1:18080/.well-known/jmap -u "admin:$temp_pass" && break
    sleep 1
  done
  [ -n "$temp_pass" ] || { echo "bootstrap password not found" >&2; exit 1; }

  local admin_account
  admin_account=$(curl -sf -u "admin:$temp_pass" http://127.0.0.1:18080/.well-known/jmap -L |
    sed -n 's/.*"urn:stalwart:jmap":"\([^"]*\)".*/\1/p')

  local bootstrap
  bootstrap=$(jmap "admin:$temp_pass" http://127.0.0.1:18080/jmap/ "{
    \"using\":[\"urn:ietf:params:jmap:core\",\"urn:stalwart:jmap\"],
    \"methodCalls\":[[\"x:Bootstrap/set\",{\"accountId\":\"$admin_account\",\"update\":{\"singleton\":{
      \"serverHostname\":\"localhost\",\"defaultDomain\":\"$DOMAIN\",
      \"requestTlsCertificate\":false,\"generateDkimKeys\":false}}},\"0\"]]}")
  local admin_user admin_pass
  admin_user=$(echo "$bootstrap" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p')
  admin_pass=$(echo "$bootstrap" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
  [ -n "$admin_pass" ] || { echo "bootstrap failed: $bootstrap" >&2; exit 1; }

  docker restart "$NAME" >/dev/null
  for _ in $(seq 1 30); do
    curl -sfk -o /dev/null -u "$admin_user:$admin_pass" https://localhost/.well-known/jmap && break
    sleep 1
  done

  local session admin_id domain_id
  session=$(curl -sfk -u "$admin_user:$admin_pass" https://localhost/.well-known/jmap -L)
  admin_id=$(echo "$session" | sed -n 's/.*"urn:stalwart:jmap":"\([^"]*\)".*/\1/p')
  domain_id=$(jmap "$admin_user:$admin_pass" https://localhost/jmap/ "{
    \"using\":[\"urn:ietf:params:jmap:core\",\"urn:stalwart:jmap\"],
    \"methodCalls\":[[\"x:Domain/get\",{\"accountId\":\"$admin_id\",\"properties\":[\"name\"]},\"0\"]]}" |
    sed -n 's/.*"id":"\([^"]*\)".*/\1/p')

  # Stalwart object lists are id-keyed maps, not arrays.
  jmap "$admin_user:$admin_pass" https://localhost/jmap/ "{
    \"using\":[\"urn:ietf:params:jmap:core\",\"urn:stalwart:jmap\"],
    \"methodCalls\":[[\"x:Account/set\",{\"accountId\":\"$admin_id\",\"create\":{\"u\":{
      \"@type\":\"User\",\"name\":\"$TEST_USER\",\"domainId\":\"$domain_id\",
      \"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$TEST_PASS\"}}}}},\"0\"]]}" |
    grep -q '"created"' || { echo "creating $TEST_USER failed" >&2; exit 1; }

  echo "STALWART_ADMIN=$admin_user"
  echo "STALWART_ADMIN_PASS=$admin_pass"
  echo "KISKADEE_TEST_JMAP_URL=https://localhost/.well-known/jmap"
  echo "KISKADEE_TEST_USER=$TEST_USER@$DOMAIN"
  echo "KISKADEE_TEST_PASS=$TEST_PASS"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
