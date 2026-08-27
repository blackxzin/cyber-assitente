#!/usr/bin/env bash
# Compiles the Cyber Bridge Burp extension against the locally installed
# burpsuite.jar (which bundles the Montoya API classes) — no Maven/Gradle
# and no network access needed.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BURP_JAR="${BURP_JAR:-/usr/share/burpsuite/burpsuite.jar}"
OUT="$DIR/out"
JAR="$DIR/cyber-bridge.jar"

if [[ ! -f "$BURP_JAR" ]]; then
    echo "burpsuite.jar not found at $BURP_JAR (set BURP_JAR=... to override)" >&2
    exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

javac -cp "$BURP_JAR" -d "$OUT" "$DIR"/src/cyberbridge/*.java

jar --create --file "$JAR" -C "$OUT" .

echo "Built: $JAR"
echo "Load it in Burp via Extensions > Add > Extension type: Java > select this file."
