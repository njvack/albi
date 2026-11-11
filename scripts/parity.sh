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
# Prints one line per section (top-level fields, each category, custom
# checks), then a diff for each section that differs. Exits non-zero if any
# section differs.
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

# Split a report into sections, one file each: report (the top-level
# fields), each category under <categories>, and custom-checks.
split_report() {
  mkdir -p $2
  perl -ne '
    BEGIN { $s = "report" }
    if (/^    <entry name="([^"]+)">/) { $s = $1 }
    elsif (/^  <custom-checks>/) { $s = "custom-checks" }
    open my $fh, ">>", "'$2'/$s" or die; print $fh $_; close $fh;
    if (/^    <\/entry>/ || /^  <\/custom-checks>/) { $s = "report" }
  ' $1
}
split_report $work/ref.xml $work/ref.d
split_report $work/ours.xml $work/ours.d

order=(report host-info anti-malware disk-backup disk-encryption firewall patch-management data-loss-prevention custom-checks)
for s in $work/ref.d/*(N:t) $work/ours.d/*(N:t); do
  (( ${order[(Ie)$s]} )) || order+=($s)
done

differ=()
for s in $order; do
  [[ -e $work/ref.d/$s || -e $work/ours.d/$s ]] || continue
  touch $work/ref.d/$s $work/ours.d/$s
  if cmp -s $work/ref.d/$s $work/ours.d/$s; then
    printf '%-22s same\n' $s
  else
    printf '%-22s DIFFERENT\n' $s
    differ+=($s)
  fi
done

if (( ${#differ} == 0 )); then
  print "parity: identical to ${ref:t} ($(grep -c '<Prod ' $work/ours.xml) products)"
  exit 0
fi
for s in $differ; do
  print -- "\n=== $s (${ref:t} -, hipreport +)"
  diff -u --label ${ref:t} --label hipreport $work/ref.d/$s $work/ours.d/$s | tail -n +3 || true
done
print -u2 -- "\nparity: ${#differ} section(s) differ: ${(j:, :)differ}"
print -u2 -- "--- hipreport stderr"; cat $work/ours.err >&2
exit 1
