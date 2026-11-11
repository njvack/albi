#!/bin/zsh -f
# Compare Albi's hipreport with a reference reporter on this Mac, element
# for element.
#
#   scripts/parity.sh REFERENCE [HIPREPORT]
#
# REFERENCE is hipreport.zsh or the Go hipreport, both from
# njvack/openconnect-hipreports. HIPREPORT defaults to the release build.
# Both get the same openconnect-style arguments, and hipreport also loads
# contrib/, which holds the reference's third-party checks. Differences that are
# expected are normalized first: generate-time; Packet Filter's
# is-enabled, which hipreport.zsh reads with `sudo -n pfctl` and hipreport
# reports as n/a unless it runs as root; and whitespace-only element
# content (hipreport.zsh writes an empty list as <list>, newline, </list>).
# Exits non-zero on any other difference.
emulate -R zsh
setopt err_exit pipe_fail

here=${0:A:h}
ref=${1:?usage: parity.sh REFERENCE [HIPREPORT]}
ours=${2:-$here/../.build/release/hipreport}
work=$(mktemp -d)
trap 'rm -rf $work' EXIT

args=(--cookie "authcookie=x&portal=p&user=${USER}&domain=Parity+Test&computer=${HOST%%.*}"
      --client-ip 10.99.0.2 --md5 0123456789abcdef0123456789abcdef --client-os Mac)

normalize() {
  perl -0pe '
    s{<generate-time>[^<]*</generate-time>}{<generate-time/>}g;
    s{<([\w-]+)>\s*</\1>}{<$1/>}g;
    s{(name="Packet Filter"[^>]*/>\s*<is-enabled>)[^<]*(</is-enabled>)}{$1-$2}g;
  '
}

if [[ $ref == *.zsh ]]; then
  zsh -f $ref $args 2>$work/ref.err | normalize >$work/ref.xml
else
  $ref --checks-dir /nonexistent $args 2>$work/ref.err | normalize >$work/ref.xml
fi
$ours --checks-dir /nonexistent --dev-checks $here/../contrib $args 2>$work/ours.err | normalize >$work/ours.xml

if diff -u $work/ref.xml $work/ours.xml; then
  print "parity: identical to ${ref:t} ($(grep -c '<Prod ' $work/ours.xml) products)"
else
  print -u2 -- "parity: reports differ (${ref:t} -, hipreport +)"
  print -u2 -- "--- hipreport stderr"; cat $work/ours.err >&2
  exit 1
fi
