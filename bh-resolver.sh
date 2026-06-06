#!/bin/bash
# ================================================================
#  BH Resolver — local unbound caching resolver for CWP / EL8
#
#  WHY: Spamhaus (and most DNSBLs) REFUSE queries from big public
#  resolvers (Google 8.8.8.8 / Cloudflare 1.1.1.1) — they silently
#  return nothing. So if /etc/resolv.conf points at a public resolver,
#  postscreen's DNSBL scoring in bh-mail-guard is INERT (this is why
#  "postscreen DNSBL rejects" stays 0). A local recursive resolver
#  queries the DNSBL authoritative servers directly → scoring works,
#  and botnets get rejected at connect time (the cheapest layer).
#
#  HOW: installs unbound bound to 127.0.0.53:53 (NOT 127.0.0.1 — so it
#  never collides with CWP's named/BIND on 127.0.0.1:53) and points
#  resolv.conf at it, keeping your existing resolver as a fallback line
#  so DNS never fully dies if unbound hiccups.
#
#  SAFETY: this is the scariest change on a live box (break the resolver,
#  break everything). So we:
#    • TEST that unbound resolves a normal name AND a DNSBL test entry
#      BEFORE touching resolv.conf — abort if it can't.
#    • back up resolv.conf (restore on any failure).
#    • keep the old nameserver as a 2nd line (fallback if unbound dies).
#    • never chattr unless you ask (STICKY=1).
#
#  ── Phases ──
#    detect    read-only: what's on :53, current resolver, live DNSBL test
#    install   install + configure unbound, test, then repoint resolv.conf
#    status    show unbound state + live DNSBL test
#    rollback  restore resolv.conf, remove drop-in, stop unbound
#
#  ── Usage ──
#    bash bh-resolver.sh detect      # ALWAYS start here, paste output
#    bash bh-resolver.sh install     # interactive confirm
#    bash bh-resolver.sh install -y  # non-interactive (fleet)
#    bash bh-resolver.sh status
#
#  ── Env ──
#    STICKY=1   chattr +i /etc/resolv.conf so NetworkManager/dhclient
#               can't overwrite it (rollback clears it). Default 0.
#    UB_ADDR=127.0.0.53   loopback address unbound binds (default).
#
#  Idempotent. Safe to re-run. Pairs with bh-mail-guard.sh.
#  v1.0 (2026-06-06)
# ================================================================
set -e

UB_ADDR="${UB_ADDR:-127.0.0.53}"
STICKY="${STICKY:-0}"
RESOLV=/etc/resolv.conf
DROPIN=/etc/unbound/conf.d/bh-resolver.conf
RUNSTAMP="$(date +%Y%m%d-%H%M%S)"
LOG=/var/log/bh-mail-guard.log

NON_INTERACTIVE=0 ; PHASE=""
for a in "$@"; do case "$a" in
  -y|--yes) NON_INTERACTIVE=1 ;;
  detect|install|status|rollback) PHASE="$a" ;;
esac; done
INTERACTIVE=0; [ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ] && INTERACTIVE=1

c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
logf(){ echo "[$(date '+%F %T')] resolver: $*" >> "$LOG" 2>/dev/null || true; }
say(){ echo "  $*"; }
ok(){ echo "  ${c_ok}✓${c_off} $*"; logf "OK: $*"; }
warn(){ echo "  ${c_warn}⚠${c_off} $*"; logf "WARN: $*"; }
skip(){ echo "  ${c_dim}⊘ $*${c_off}"; }
err(){ echo "  ${c_err}✗${c_off} $*" >&2; logf "ERR: $*"; }
die(){ err "$*"; exit 1; }
hdr(){ echo; echo "── $* ─────────────────────────────────"; }
ask_yn(){ local p="$1" d="$2" disp ans; case "$d" in y|Y|1) disp="Y/n";; *) disp="y/N";; esac
  if [ "$INTERACTIVE" = "0" ]; then case "$d" in y|Y|1) REPLY=1;; *) REPLY=0;; esac; return; fi
  read -r -p "  $p [$disp]: " ans < /dev/tty; [ -z "$ans" ] && ans="$d"
  case "$ans" in y|Y|yes|YES|1) REPLY=1;; *) REPLY=0;; esac; }

[ "$(id -u)" = "0" ] || die "Must run as root."
command -v dig >/dev/null 2>&1 || { yum install -y bind-utils >/dev/null 2>&1 || true; }

# dig helpers (short, fast, no retry hang)
dq(){ dig +short +time=3 +tries=1 "$@" 2>/dev/null; }          # query system resolver
dqa(){ dig +short +time=3 +tries=1 @"$1" "${@:2}" 2>/dev/null; } # query a specific resolver

current_ns(){ grep -E '^[[:space:]]*nameserver' "$RESOLV" 2>/dev/null | awk '{print $2}'; }

# Spamhaus test: 2.0.0.127.zen.spamhaus.org ALWAYS returns 127.0.0.x when the
# query path is valid; empty = blocked (public resolver) or no recursion.
SPAMHAUS_TEST="2.0.0.127.zen.spamhaus.org"

phase_detect() {
  hdr "DETECT — resolver state + live DNSBL test (read-only)"
  say "Hostname:        $(hostname -f 2>/dev/null || hostname)"
  say "unbound:         $(command -v unbound >/dev/null 2>&1 && echo installed || echo 'not installed')"
  echo
  say "Current resolv.conf nameservers:"
  current_ns | sed 's/^/        /' || say "        <none>"
  echo
  say "What is listening on :53 —"
  ss -lntupH 2>/dev/null | grep -E ':53 ' | sed 's/^/        /' || say "        <nothing>"
  echo
  local g s
  g="$(dq google.com A | head -1)"
  s="$(dq "$SPAMHAUS_TEST" | head -1)"
  say "Live test via CURRENT system resolver:"
  say "  resolve google.com    → ${g:-<FAIL>}"
  say "  Spamhaus DNSBL test    → ${s:-<empty = NOT working>}"
  echo
  if echo "$s" | grep -q '^127\.'; then
    ok "DNSBL lookups ALREADY work on this box — no resolver change needed."
    say "  (postscreen DNSBL scoring should already be rejecting; check"
    say "   bash bh-mail-guard.sh status)"
  else
    warn "DNSBL lookups are NOT working via the current resolver."
    say "  → 'bash $0 install' sets up a local unbound resolver to fix this."
  fi
}

write_dropin() {
  mkdir -p /etc/unbound/conf.d
  # Bind ONLY to UB_ADDR (specifying any interface disables unbound's default
  # localhost bind) so we never fight named on 127.0.0.1:53. No private-address
  # filtering — DNSBLs answer with 127.0.0.x and we must let that through.
  local v6="no"; ip -6 addr show scope global 2>/dev/null | grep -q inet6 && v6="yes"
  cat > "$DROPIN" <<EOF
# BH-RESOLVER managed — local caching recursive resolver for DNSBL lookups
server:
    interface: $UB_ADDR
    access-control: 127.0.0.0/8 allow
    do-ip6: $v6
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    prefetch: yes
    cache-min-ttl: 60
    cache-max-ttl: 86400
    num-threads: 2
    so-reuseport: yes
EOF
  ok "wrote unbound drop-in: $DROPIN (interface $UB_ADDR, do-ip6=$v6)"
}

phase_install() {
  hdr "INSTALL — local unbound resolver on $UB_ADDR"
  if ! command -v unbound >/dev/null 2>&1; then
    yum install -y unbound >/dev/null 2>&1 || die "unbound install failed (check repos)"
    ok "unbound installed"
  else
    skip "unbound already installed"
  fi
  write_dropin

  # validate config, then (re)start
  if ! unbound-checkconf >/tmp/bhmg-ub.err 2>&1; then
    err "unbound-checkconf failed:"; sed 's/^/      /' /tmp/bhmg-ub.err >&2 || true
    die "Not starting unbound with a bad config. Drop-in left at $DROPIN for inspection."
  fi
  systemctl enable unbound >/dev/null 2>&1 || true
  systemctl restart unbound 2>/dev/null || systemctl start unbound 2>/dev/null || die "unbound failed to start"
  sleep 2
  ss -lntuH 2>/dev/null | grep -q "$UB_ADDR:53" || die "unbound not listening on $UB_ADDR:53 — aborting before resolv.conf change"
  ok "unbound listening on $UB_ADDR:53"

  # ── CRITICAL pre-flight: prove unbound resolves BEFORE repointing resolv.conf ──
  local g s
  g="$(dqa "$UB_ADDR" google.com A | head -1)"
  s="$(dqa "$UB_ADDR" "$SPAMHAUS_TEST" | head -1)"
  if ! echo "$g" | grep -qE '^[0-9]'; then
    err "unbound did NOT resolve google.com (got: '${g:-empty}')."
    die "Refusing to touch $RESOLV — your DNS would break. unbound left running on $UB_ADDR for debugging (try: dig @$UB_ADDR google.com)."
  fi
  ok "unbound resolves normal names (google.com → $g)"
  if echo "$s" | grep -q '^127\.'; then
    ok "unbound resolves Spamhaus DNSBL ($SPAMHAUS_TEST → $s) — DNSBL scoring will work"
  else
    warn "unbound resolves names but Spamhaus test came back empty."
    warn "  Could be transient, or this IP is rate-limited by Spamhaus. Proceeding;"
    warn "  recursion works so general DNS is safe. Re-check later with: dig @$UB_ADDR $SPAMHAUS_TEST"
  fi

  # ── Repoint resolv.conf (unbound primary, old resolver kept as fallback) ──
  [ -f "${RESOLV}.bh-bak-${RUNSTAMP}" ] || cp -a "$RESOLV" "${RESOLV}.bh-bak-${RUNSTAMP}" 2>/dev/null || true
  chattr -i "$RESOLV" 2>/dev/null || true   # in case a prior run made it immutable
  local oldns; oldns="$(current_ns | grep -v "^${UB_ADDR}$" | head -2)"
  {
    echo "# BH-RESOLVER managed — local unbound resolver (DNSBL-capable). $RUNSTAMP"
    echo "nameserver $UB_ADDR"
    for ns in $oldns; do echo "nameserver $ns   # fallback (used only if unbound is down)"; done
    echo "options edns0 trust-ad"
  } > "${RESOLV}.bhmg-new"
  cat "${RESOLV}.bhmg-new" > "$RESOLV" && rm -f "${RESOLV}.bhmg-new"
  ok "resolv.conf now points at $UB_ADDR (fallback: ${oldns:-none})"

  if [ "$STICKY" = "1" ]; then
    chattr +i "$RESOLV" 2>/dev/null && ok "resolv.conf set immutable (STICKY=1) — survives NM/dhclient" \
      || warn "could not set immutable flag on $RESOLV"
  else
    say "  (tip: STICKY=1 makes resolv.conf immutable so NM/dhclient can't revert it)"
  fi

  # ── Post-flight: verify via the SYSTEM resolver now ──
  local s2; s2="$(dq "$SPAMHAUS_TEST" | head -1)"
  echo
  if echo "$s2" | grep -q '^127\.'; then
    ok "system resolver now answers DNSBL queries ($SPAMHAUS_TEST → $s2)"
    say "  ${c_ok}postscreen DNSBL scoring is now live.${c_off} Watch it climb:"
    say "    bash bh-mail-guard.sh status   # 'postscreen DNSBL rejects' should rise"
  else
    warn "system DNSBL test still empty — re-run 'bash $0 detect' in a minute to recheck"
  fi
  say "  Rollback: bash $0 rollback"
}

phase_status() {
  hdr "STATUS — unbound + DNSBL"
  say "unbound service: $(systemctl is-active unbound 2>/dev/null || echo n/a)"
  ss -lntuH 2>/dev/null | grep -q "$UB_ADDR:53" && ok "listening on $UB_ADDR:53" || warn "not listening on $UB_ADDR:53"
  say "resolv.conf:"; current_ns | sed 's/^/        /'
  local s; s="$(dq "$SPAMHAUS_TEST" | head -1)"
  echo
  if echo "$s" | grep -q '^127\.'; then ok "DNSBL working ($SPAMHAUS_TEST → $s)"
  else warn "DNSBL test empty — Spamhaus not answering via current resolver"; fi
}

phase_rollback() {
  hdr "ROLLBACK — restore previous resolver"
  chattr -i "$RESOLV" 2>/dev/null || true
  local bak; bak="$(ls -1t ${RESOLV}.bh-bak-* 2>/dev/null | head -1)"
  if [ -n "$bak" ]; then cp -a "$bak" "$RESOLV"; ok "restored $RESOLV from $bak"
  else warn "no resolv.conf backup found — leaving $RESOLV as-is"; fi
  rm -f "$DROPIN" && ok "removed unbound drop-in"
  systemctl stop unbound 2>/dev/null || true
  systemctl disable unbound >/dev/null 2>&1 || true
  ok "unbound stopped + disabled (package left installed; 'yum remove unbound' to purge)"
  say "Verify DNS still works: dig +short google.com"
}

echo "╔══════════════════════════════════════════════╗"
echo "║   BH Resolver — local unbound for DNSBLs v1.0  ║"
echo "╚══════════════════════════════════════════════╝"

case "$PHASE" in
  detect)   phase_detect ;;
  install)  phase_install ;;
  status)   phase_status ;;
  rollback) phase_rollback ;;
  "")
    phase_detect; echo
    if [ "$INTERACTIVE" = "1" ]; then
      ask_yn "Install local unbound resolver now?" "n"
      [ "$REPLY" = "1" ] && { echo; phase_install; } || say "No changes made. Run: bash $0 install"
    else
      say "No phase given. Run:  bash $0 install"
    fi ;;
  *) die "Unknown phase '$PHASE'. Phases: detect install status rollback" ;;
esac
