#!/usr/bin/env bash
#
# Build the C6000 Ghidra extension.
#
# This exists because `buildExtension` does NOT compile SLEIGH.  A zip built
# without compiled SLEIGH installs cleanly and then fails at import time with
# "Unsupported language".  This script compiles every .slaspec first, then
# builds, then verifies that the zip really contains the .sla files.
#
# Usage:
#   tools/build.sh [--install [GHIDRA_DIR]]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra install root (default: Homebrew's opt/ghidra)
#   JAVA_HOME           JDK 21 home (Ghidra 12 rejects newer JDKs)
#   GHIDRA_WORK         scratch directory for user.home / Gradle caches
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${GHIDRA_WORK:-$ROOT/scratch/build}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '\n== %s\n' "$*"; }

resolve_ghidra() {
  if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then printf '%s\n' "$GHIDRA_INSTALL_DIR"
  elif [ -x /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless ]; then
    printf '%s\n' /opt/homebrew/opt/ghidra/libexec
  else
    ls -d /opt/homebrew/Cellar/ghidra/*/libexec 2>/dev/null | sort -V | tail -1
  fi
}

resolve_java_home() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME"; return
  fi
  for c in /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
           /opt/homebrew/opt/openjdk@21 \
           /usr/lib/jvm/temurin-21-jdk-amd64 \
           /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home; do
    [ -x "$c/bin/java" ] && { printf '%s\n' "$c"; return; }
  done
}

GHIDRA="$(resolve_ghidra)"
JH="$(resolve_java_home)"
[ -n "$GHIDRA" ] && [ -x "$GHIDRA/support/analyzeHeadless" ] || \
  die "no Ghidra install found; set GHIDRA_INSTALL_DIR"
[ -n "$JH" ] || die "no JDK 21 found; set JAVA_HOME (Ghidra 12 rejects newer JDKs)"

export PATH="$JH/bin:$PATH"
# Ghidra writes under $HOME during bootstrap; keep that inside the workspace so
# the build works in CI and inside a sandbox.
mkdir -p "$WORK/home" "$WORK/gradle" "$WORK/project"
export _JAVA_OPTIONS="-Duser.home=$WORK/home"
export GRADLE_USER_HOME="$WORK/gradle"

note "environment"
printf '  Ghidra    : %s\n  JDK       : %s\n  user.home : %s\n' \
  "$GHIDRA" "$JH" "$WORK/home"

note "compiling SLEIGH"
for spec in "$ROOT"/data/languages/*.slaspec; do
  ( cd "$ROOT" && "$GHIDRA/support/sleigh" "$spec" )
done
for sla in "$ROOT"/data/languages/*.sla; do
  [ -f "$sla" ] || die "SLEIGH produced no .sla - the extension would be unloadable"
  printf '  %s\n' "$(basename "$sla")"
done

note "building extension"
( cd "$ROOT" && "$GHIDRA/support/gradle/gradlew" -q \
    -PGHIDRA_INSTALL_DIR="$GHIDRA" buildExtension )
DIST="$(ls -t "$ROOT"/dist/*_C6000.zip 2>/dev/null | head -1)"
[ -n "$DIST" ] || die "buildExtension produced no zip"

note "verifying zip contents"
for sla in c6000_le c6000_be; do
  unzip -t "$DIST" "C6000/data/languages/$sla.sla" >/dev/null || \
    die "built zip is missing data/languages/$sla.sla"
done
unzip -t "$DIST" 'C6000/data/languages/c6000.opinion' >/dev/null || \
  die "built zip is missing the loader opinion"
printf '  %s\n' "$DIST"

if [ "${1:-}" = "--install" ]; then
  TARGET="${2:-${LOCAL_GHIDRA:-}}"
  [ -n "$TARGET" ] || die "--install needs a target Ghidra directory"
  [ -d "$TARGET/Ghidra" ] || die "not a Ghidra install: $TARGET"
  note "installing into $TARGET"
  rm -rf "$TARGET/Ghidra/Extensions/C6000"
  mkdir -p "$TARGET/Ghidra/Extensions"
  unzip -q -o "$DIST" -d "$TARGET/Ghidra/Extensions/"
  printf '  installed\n'
fi

note "ok"
