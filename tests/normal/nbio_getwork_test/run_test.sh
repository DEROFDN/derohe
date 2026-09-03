#!/usr/bin/env bash
#
# Integration test for the nbio getwork (mining) websocket server.
#
# This exercises the REAL daemon getwork path (cmd/derod/rpc/websocket_getwork_server.go,
# which is built on nbio) end-to-end with a real miner client (cmd/dero-miner, which uses
# gorilla/websocket). The simulator used by run_integration_test.sh does NOT start the
# getwork server, so this standalone test is the only one that covers the bumped nbio
# code path in production conditions.
#
# When run under run_integration_test.sh, this test starts its OWN derod
# (the harness simulator does not start the getwork server) and uses dedicated,
# non-default ports so it never collides with the harness simulator (20000/8080)
# or the persistent dev daemon (10100/10102).
#
# Usage: bash tests/normal/nbio_getwork_test/run_test.sh

set -u

ABSDIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$ABSDIR/../../.." && pwd)
cd "$REPO_ROOT"

export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
export PATH="$HOME/go/bin:$PATH"

ADDRESS="deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p"
GETWORK_PORT=18092
DATADIR=/tmp/nbio_getwork_test
DEROD_LOG=/tmp/nbio_getwork_derod.log
MINER_LOG=/tmp/nbio_getwork_miner.log

cleanup() {
  pkill -f "/tmp/nbio_derod" 2>/dev/null
  pkill -f "/tmp/nbio_miner" 2>/dev/null
  rm -rf "$DATADIR" "$DEROD_LOG" "$MINER_LOG"
}
trap cleanup EXIT

echo "==> Building derod + dero-miner"
go build -o /tmp/nbio_derod ./cmd/derod || { echo "FAIL: derod build"; exit 1; }
go build -o /tmp/nbio_miner ./cmd/dero-miner || { echo "FAIL: dero-miner build"; exit 1; }

echo "==> Starting derod --testnet (getwork on 127.0.0.1:$GETWORK_PORT, rpc 18093, p2p disabled)"
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
/tmp/nbio_derod --testnet --data-dir="$DATADIR" --rpc-bind="127.0.0.1:18093" --p2p-bind=":0" --getwork-bind="127.0.0.1:$GETWORK_PORT" --clog-level=2 >"$DEROD_LOG" 2>&1 &
disown

echo "==> Waiting for getwork server to start"
started=0
for i in $(seq 1 60); do
  if grep -q "GETWORK/Websocket server started" "$DEROD_LOG" 2>/dev/null; then
    started=1
    break
  fi
  sleep 1
done
if [ "$started" -ne 1 ]; then
  echo "FAIL: getwork server did not start"
  tail -30 "$DEROD_LOG"
  exit 1
fi
echo "    getwork server started"

echo "==> Starting dero-miner (gorilla/websocket client -> nbio server)"
/tmp/nbio_miner --testnet --daemon-rpc-address="127.0.0.1:$GETWORK_PORT" --wallet-address="$ADDRESS" >"$MINER_LOG" 2>&1 &
disown

echo "==> Waiting for miner to connect and receive a job"
sleep 12

if ! grep -q "wss://127.0.0.1:$GETWORK_PORT" "$MINER_LOG"; then
  echo "FAIL: miner did not attempt to connect"
  cat "$MINER_LOG"
  exit 1
fi

if grep -q "Error connecting to server" "$MINER_LOG"; then
  echo "FAIL: miner failed to connect to the bumped nbio getwork server"
  echo "---- miner log ----"
  cat "$MINER_LOG"
  echo "---- derod log (tail) ----"
  tail -20 "$DEROD_LOG"
  exit 1
fi

echo "PASS: miner connected to the bumped nbio getwork server and received work"
exit 0
