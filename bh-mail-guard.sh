#!/bin/bash
# ================================================================
#  BH Mail Guard — layered anti-spam hardening for CWP / Postfix
#  (AlmaLinux 8 / EL8, Postfix + Amavis + SpamAssassin + Policyd)
#
#  PHILOSOPHY: fight spam front-to-back, cheapest layer first.
#    1. postscreen   — reject botnets at connect time (pre-DATA),
#                      weighted DNSBL scoring + pregreet test.
#    2. restrictions — HELO/FQDN/unknown-domain rejects in smtpd.
#    3. greylist     — postgrey w/ smart whitelist (ESPs not delayed).
#    4. dmarc        — opendmarc inbound (mark, don't reject by default).
#    5. sa-tune      — SpamAssassin Bayes + KAM rules + network tests
#                      (the expensive layer now only sees survivors).
#
#  Each layer shrinks what the next must handle, so by the time mail
#  reaches Amavis/SA it's a trickle — and the early layers use
#  BEHAVIORAL signals, not blunt IP blocks, so legit senders aren't
#  collaterally blocked (important for BD ecommerce customers).
#
#  CWP-AWARE: CWP's "Rebuild Postfix Configuration" button regenerates
#  main.cf / master.cf and WIPES our changes. We install a heal cron
#  (every 10 min) that re-asserts every BH key + validates with
#  `postfix check` before reloading. Same self-healing pattern as
#  bh-server-ops / cwp-custom-php. NOTHING is made immutable (chattr)
#  because CWP must stay able to add domains / DKIM keys.
#
#  SURGICAL: restriction + milter lists are APPENDED to, never
#  overwritten — so CWP's reject_unauth_destination (anti-open-relay),
#  Policyd (cluebringer) check_policy_service, and opendkim milter all
#  survive untouched. We only add what's missing.
#
#  Idempotent. Safe to re-run. Validates before every reload.
#
#  ── Phases ──────────────────────────────────────────────────────
#    detect        show what's installed / current state (read-only)
#    postscreen    enable postscreen + weighted DNSBLs in master.cf
#    restrictions  harden smtpd HELO/sender/recipient restrictions
#    greylist      install + wire postgrey with smart ESP whitelist
#    dmarc         install + wire opendmarc (inbound, mark-only)
#    sa-tune       SpamAssassin Bayes + KAM ruleset + network tests
#    heal-install  install the CWP-rebuild self-heal cron only
#    status        show live counters (rejections, greylist, etc.)
#    all           run postscreen→restrictions→greylist→dmarc→sa-tune
#                  + heal-install (the full recommended deployment)
#
#  ── Usage ───────────────────────────────────────────────────────
#    bash bh-mail-guard.sh detect          # always start here
#    bash bh-mail-guard.sh all             # full deploy (interactive)
#    bash bh-mail-guard.sh all -y          # full deploy, no prompts
#    bash bh-mail-guard.sh status          # check after a few hours
#
#  ── Env toggles (override defaults) ─────────────────────────────
#    DEEP_PROTOCOL_TESTS=1   enable postscreen after-220 tests
#                            (extra catch, but adds a retry delay like
#                            greylisting — off by default to avoid
#                            double-delay when greylist is on)
#    GREYLIST_DELAY=120      seconds postgrey defers first contact
#    DMARC_REJECT=1          opendmarc hard-rejects p=reject failures
#                            (default 0 = mark only — much safer)
#    INSTALL_KAM=1           add KAM SpamAssassin ruleset channel
#    DNSBL_THRESHOLD=3       postscreen score needed to reject
#    ENABLE_HASHBL=0         skip enabling the SpamAssassin HashBL plugin
#                            (default 1 = uncomment its stub in v342.pre so
#                            KAM's hashbl rules fire + lint is clean)
#
#  ⚠️  Run `detect` first. Deploy on ONE server, watch `status` +
#      maillog for a day, THEN roll to the fleet. postscreen edits
#      master.cf (the riskiest change) — prefer a low-traffic window.
#
#  v1.0.8 (2026-06-06) — sa-tune auto-enables the HashBL plugin (uncomments
#    the commented stub CWP ships in v342.pre) so KAM's hashbl rules fire and
#    `spamassassin --lint` is clean — no more "unknown eval check_hashbl_emails"
#    warnings. Only uncomments an existing stub (never adds a loadplugin for a
#    missing module). Toggle off with ENABLE_HASHBL=0.
#  v1.0.7 (2026-06-06) — sa-tune now VERIFIES amavisd actually started after
#    the restart (it used to print "restarted" blindly). On IPv6-disabled CWP
#    boxes amavis 2.13 fails to bind ::1:10024 and stays down silently while
#    postfix queues all inbound mail — now flagged loudly with the IPv4-bind
#    fix ($inet_socket_bind='127.0.0.1'; $inet_socket_port=10024). Hit on s4.
#  v1.0.6 (2026-06-06) — KAM network calls can no longer hang the deploy.
#    Added curl --connect-timeout/--max-time + wget --timeout on the key
#    fetch, and `timeout 180` on sa-update (hit on s4 — a slow route to
#    mcgrail.com stalled the whole run). A timeout now just skips KAM
#    (bonus-only) and the deploy continues.
#  v1.0.5 (2026-06-06) — fix KAM key URL. McGrail renamed the key in 2026;
#    the old downloads/MCGRAIL-GPG.KEY now 404s (confirmed on the fleet).
#    Correct URL: downloads/kam.sa-channels.mcgrail.com.key (key id 24C063D8,
#    fpr 21D9 7142 272C 9066 FCAA 792B 4A15 6DA5 24C0 63D8).
#  v1.0.4 (2026-06-06) — robust + self-diagnosing KAM ruleset import. Now
#    validates the downloaded key is a real PGP block (a 404 HTML page was
#    silently breaking --import), captures + prints the real error, and
#    treats `sa-update` exit 1 as SUCCESS ("no new rules" — only >=2 is a
#    real failure). Guarded against set -e. Companion `bh-resolver.sh` added
#    to the repo to install a local unbound resolver so the postscreen DNSBL
#    layer actually scores (Spamhaus ignores public resolvers).
#  v1.0.3 (2026-06-06) — status display fixes (cosmetic). grep -c already
#    prints 0 on no match, so the `|| echo 0` double-printed; replaced with a
#    `cnt()` helper (`|| true`). Top-rejected-IPs now scans ALL reject layers
#    (reverse-DNS/HELO/blocked-using), not just postscreen. First live deploy
#    on biswashost confirmed working: 105 HELO + 93 rDNS rejects + 802
#    greylist deferrals within minutes; all 5 services active.
#  v1.0.2 (2026-06-06) — CRITICAL restriction-list fix + postgrey start fix.
#    (a) The token-list helper normalized commas→spaces then spaces→commas,
#        which SPLIT multi-word entries like `check_policy_service inet:...`
#        and `reject_rbl_client zen.spamhaus.org` into two broken tokens —
#        mangling CWP's Policyd + RBL lines. Replaced with comma-only
#        `pc_append_one` / `pc_harden_list` (+ matching `pc_one`/`pc_hard`
#        in the heal cron) that never split on an inner space.
#    (b) postgrey now runs FOREGROUND (Type=simple, no -d, no PIDFile): the
#        stock unit is Type=forking w/ PIDFile=/var/run/postgrey.pid and a
#        PID-path mismatch made systemd time out + kill it in a restart loop,
#        even though it bound to :10023 fine.
#    Restore the pre-run main.cf backup and re-run `all` on any box that ran
#    v1.0–v1.0.1 (their recipient_restrictions are mangled).
#  v1.0.1 (2026-06-06) — greylist robustness (first live deploy on
#    biswashost). postgrey now runs in INET mode via a systemd drop-in
#    (unix-socket mode silently failed to start on CWP). Added
#    smtpd_policy_service_default_action=DUNNO (fail-open: a dead policy
#    service must never 451-defer legit mail) + stale unix-socket
#    cleanup in both the greylist phase and the heal cron.
#  v1.0 (2026-06-06) — initial build.
# ================================================================

set -e

# ─────────────────────────── defaults ───────────────────────────
DEEP_PROTOCOL_TESTS="${DEEP_PROTOCOL_TESTS:-0}"
GREYLIST_DELAY="${GREYLIST_DELAY:-120}"
GREYLIST_MAX_AGE="${GREYLIST_MAX_AGE:-35}"
DMARC_REJECT="${DMARC_REJECT:-0}"
INSTALL_KAM="${INSTALL_KAM:-1}"
DNSBL_THRESHOLD="${DNSBL_THRESHOLD:-3}"
POSTGREY_PORT="${POSTGREY_PORT:-10023}"
OPENDMARC_PORT="${OPENDMARC_PORT:-8893}"

STATE_DIR=/var/lib/bh-mail-guard
LOG=/var/log/bh-mail-guard.log
POSTFIX_DIR=/etc/postfix
MAIN_CF="$POSTFIX_DIR/main.cf"
MASTER_CF="$POSTFIX_DIR/master.cf"
SA_DIR=/etc/mail/spamassassin
SA_CF="$SA_DIR/bh_mail_guard.cf"
RUNSTAMP="$(date +%Y%m%d-%H%M%S)"

# ─── interactive / non-interactive ───
NON_INTERACTIVE=0
PHASE=""
for a in "$@"; do
  case "$a" in
    -y|--yes|--non-interactive) NON_INTERACTIVE=1 ;;
    detect|postscreen|restrictions|greylist|dmarc|sa-tune|heal-install|status|all) PHASE="$a" ;;
  esac
done
INTERACTIVE=0
[ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ] && INTERACTIVE=1

# ─── output helpers ───
c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ts()  { date '+%Y-%m-%d %H:%M:%S'; }
logf(){ mkdir -p "$STATE_DIR"; echo "[$(ts)] $*" >> "$LOG"; }
say() { echo "  $*"; }
ok()  { echo "  ${c_ok}✓${c_off} $*"; logf "OK: $*"; }
warn(){ echo "  ${c_warn}⚠${c_off} $*"; logf "WARN: $*"; }
skip(){ echo "  ${c_dim}⊘ $* ${c_off}"; }
err() { echo "  ${c_err}✗${c_off} $*" >&2; logf "ERR: $*"; }
die() { err "$*"; exit 1; }
hdr() { echo; echo "── $* ─────────────────────────────────" ; }

ask_yn() {
  # ask_yn "prompt" "y|n"  → sets REPLY=1/0
  local prompt="$1" default="$2" disp ans
  case "$default" in y|Y|1) disp="Y/n" ;; *) disp="y/N" ;; esac
  if [ "$INTERACTIVE" = "0" ]; then
    case "$default" in y|Y|1) REPLY=1 ;; *) REPLY=0 ;; esac; return
  fi
  read -r -p "  $prompt [$disp]: " ans < /dev/tty
  [ -z "$ans" ] && ans="$default"
  case "$ans" in y|Y|yes|YES|1) REPLY=1 ;; *) REPLY=0 ;; esac
}

# ─────────────────────────── detection ───────────────────────────
PANEL="" ; POSTCONF="" ; HAS_POSTSCREEN=0 ; HAS_POSTGREY=0
HAS_OPENDMARC=0 ; HAS_OPENDKIM=0 ; HAS_AMAVIS=0 ; HAS_SA=0
HAS_POLICYD=0 ; HAS_EPEL=0

detect_env() {
  [ "$(id -u)" = "0" ] || die "Must run as root."
  POSTCONF="$(command -v postconf || echo /usr/sbin/postconf)"
  [ -x "$POSTCONF" ] || die "Postfix not found (no postconf). Is this a mail server?"
  [ -f "$MAIN_CF" ]   || die "No $MAIN_CF — Postfix not configured."
  [ -f "$MASTER_CF" ] || die "No $MASTER_CF."

  [ -d /usr/local/cwpsrv ] && PANEL="cwp" || PANEL="generic"

  grep -qE '^[[:space:]]*[^#].*postscreen' "$MASTER_CF" 2>/dev/null && HAS_POSTSCREEN=1
  command -v postgrey  >/dev/null 2>&1 && HAS_POSTGREY=1
  command -v opendmarc >/dev/null 2>&1 && HAS_OPENDMARC=1
  command -v opendkim  >/dev/null 2>&1 && HAS_OPENDKIM=1
  ( command -v amavisd >/dev/null 2>&1 || [ -d /etc/amavisd ] || [ -f /etc/amavisd.conf ] ) && HAS_AMAVIS=1
  ( command -v spamassassin >/dev/null 2>&1 || [ -d "$SA_DIR" ] ) && HAS_SA=1
  "$POSTCONF" -h smtpd_recipient_restrictions 2>/dev/null | grep -q '10031\|cluebringer\|policyd' && HAS_POLICYD=1
  rpm -q epel-release >/dev/null 2>&1 && HAS_EPEL=1
}

# ─────────────────────── postconf helpers ───────────────────────
pc_get() { "$POSTCONF" -h "$1" 2>/dev/null; }
pc_set() {
  # pc_set KEY VALUE  — set only if different (keeps maillog quiet)
  local key="$1" val="$2" cur
  cur="$(pc_get "$key")"
  if [ "$cur" != "$val" ]; then
    "$POSTCONF" -e "$key=$val"
    logf "main.cf set $key=$val (was: ${cur:-<unset>})"
    return 0
  fi
  return 1
}
_pc_entries() {
  # Split a postconf restriction list into one ENTRY per line, splitting on
  # COMMA ONLY. Postfix entries like `check_policy_service inet:127.0.0.1:10031`
  # and `reject_rbl_client zen.spamhaus.org` contain a space between the
  # keyword and its argument — that space must NOT be treated as a separator.
  # (The original helper did `tr ' ' ', '` and split those in half, mangling
  #  Policyd + RBL entries. This is the v1.0.2 fix.)
  pc_get "$1" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' || true
}
_pc_write() {
  # rejoin entries (one per line on stdin) into a comma-space postconf value
  local key="$1" joined
  joined="$(grep -v '^$' | paste -sd, - | sed 's/,/, /g')"
  "$POSTCONF" -e "$key=$joined"
  logf "main.cf set $key -> $joined"
}

pc_append_one() {
  # pc_append_one KEY "entry"  — append ONE entry (may contain a space, e.g.
  # 'check_policy_service inet:127.0.0.1:10023' or 'inet:127.0.0.1:8893') at
  # the END iff absent. Exact whole-entry match, never splits on inner space.
  local key="$1" entry="$2" entries
  entries="$(_pc_entries "$key")"
  printf '%s\n' "$entries" | grep -qxF "$entry" && return 1
  printf '%s\n%s\n' "$entries" "$entry" | _pc_write "$key"
  return 0
}

pc_harden_list() {
  # pc_harden_list KEY "reject_tok1 reject_tok2 ..."
  #   Append single-word reject tokens at the END iff absent. If the list has
  #   NEITHER permit_mynetworks NOR permit_sasl_authenticated, prepend both so
  #   auth/local senders are permitted BEFORE hitting the new rejects (matters
  #   for empty helo/sender lists). Existing entries are NEVER reordered — so
  #   CWP's Policyd-first ordering in recipient_restrictions is preserved.
  local key="$1" toks="$2" entries t changed=0
  entries="$(_pc_entries "$key")"
  if ! printf '%s\n' "$entries" | grep -qxE 'permit_mynetworks|permit_sasl_authenticated'; then
    entries="$(printf 'permit_mynetworks\npermit_sasl_authenticated\n%s' "$entries")"
    changed=1
  fi
  for t in $toks; do
    if ! printf '%s\n' "$entries" | grep -qxF "$t"; then
      entries="$(printf '%s\n%s' "$entries" "$t")"; changed=1
    fi
  done
  [ "$changed" = "1" ] || return 1
  printf '%s\n' "$entries" | _pc_write "$key"
  return 0
}

pc_strip_token() {
  # pc_strip_token KEY "exact entry"  — remove one comma-list entry if present
  local key="$1" sub="$2" out
  pc_get "$key" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -qxF "$sub" || return 0
  out="$(pc_get "$key" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -vxF "$sub" | paste -sd, - | sed 's/,/, /g')"
  "$POSTCONF" -e "$key=$out"
  logf "main.cf strip '$sub' from $key"
}

backup_once() {
  # back up a file once per run, tagged with the run timestamp
  local f="$1"
  [ -f "$f" ] || return 0
  local b="${f}.bh-bak-${RUNSTAMP}"
  [ -f "$b" ] || cp -a "$f" "$b"
}

validate_and_reload() {
  # postfix check; reload on success, restore newest backups on failure
  if "$POSTCONF" >/dev/null 2>&1 && postfix check 2>/tmp/bhmg-check.err; then
    if systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null; then
      ok "postfix validated + reloaded"
    else
      warn "postfix check passed but reload failed — run: systemctl restart postfix"
    fi
  else
    err "postfix check FAILED — NOT reloading. Errors:"
    sed 's/^/      /' /tmp/bhmg-check.err >&2 || true
    err "Backups from this run: ${MAIN_CF}.bh-bak-${RUNSTAMP} / ${MASTER_CF}.bh-bak-${RUNSTAMP}"
    die "Aborting before a broken config goes live. Restore the .bh-bak file if needed."
  fi
}

# ════════════════════════════ PHASES ════════════════════════════

phase_detect() {
  hdr "DETECT — current mail-server state (read-only)"
  say "Panel:            $PANEL"
  say "Hostname:         $(hostname -f 2>/dev/null || hostname)"
  say "postscreen:       $([ $HAS_POSTSCREEN = 1 ] && echo "${c_ok}enabled${c_off}" || echo "${c_warn}NOT enabled${c_off}  ← biggest missing layer")"
  say "postgrey:         $([ $HAS_POSTGREY = 1 ]  && echo "${c_ok}installed${c_off}" || echo "not installed")"
  say "opendmarc:        $([ $HAS_OPENDMARC = 1 ] && echo "${c_ok}installed${c_off}" || echo "not installed")"
  say "opendkim:         $([ $HAS_OPENDKIM = 1 ]  && echo "present (DKIM signing)" || echo "not found")"
  say "amavis:           $([ $HAS_AMAVIS = 1 ]    && echo "present" || echo "not found")"
  say "spamassassin:     $([ $HAS_SA = 1 ]        && echo "present" || echo "not found")"
  say "Policyd/cluebr.:  $([ $HAS_POLICYD = 1 ]   && echo "wired in recipient restrictions (will be preserved)" || echo "not detected")"
  say "EPEL repo:        $([ $HAS_EPEL = 1 ]      && echo present || echo "${c_warn}missing${c_off} (needed for postgrey/opendmarc)")"
  echo
  say "Current smtpd_recipient_restrictions:"
  pc_get smtpd_recipient_restrictions | sed 's/,/,\n        /g; s/^/        /'
  echo
  say "Current smtpd_milters: $(pc_get smtpd_milters || echo '<none>')"
  echo
  say "Next: ${c_ok}bash $0 all${c_off}   (or run phases individually)"
}

phase_postscreen() {
  hdr "POSTSCREEN — reject botnets at connect time"
  [ "$HAS_EPEL" = 1 ] || { yum install -y epel-release >/dev/null 2>&1 && HAS_EPEL=1 && ok "installed epel-release"; }

  backup_once "$MASTER_CF"; backup_once "$MAIN_CF"

  # 1) master.cf — swap the plain `smtp inet … smtpd` for postscreen.
  #    Leaves submission(587)/smtps(465) ALONE — those are authenticated
  #    user ports and must NOT be greeted by postscreen.
  if [ "$HAS_POSTSCREEN" = "1" ]; then
    skip "postscreen already wired in master.cf"
  else
    # match the first uncommented line that starts with smtp + ends in smtpd
    if grep -qE '^smtp[[:space:]]+inet[[:space:]].*[[:space:]]smtpd([[:space:]]|$)' "$MASTER_CF"; then
      awk '
        BEGIN{done=0}
        /^smtp[ \t]+inet[ \t]+.*[ \t]smtpd([ \t]|$)/ && !done {
          print "# BH-MAIL-GUARD-POSTSCREEN (managed by bh-mail-guard.sh)"
          print "smtp      inet  n       -       n       -       1       postscreen"
          print "smtpd     pass  -       -       n       -       -       smtpd"
          print "dnsblog   unix  -       -       n       -       0       dnsblog"
          print "tlsproxy  unix  -       -       n       -       0       tlsproxy"
          print "# END BH-MAIL-GUARD-POSTSCREEN"
          done=1; next
        }
        {print}
      ' "$MASTER_CF" > "${MASTER_CF}.bhmg-new" && mv "${MASTER_CF}.bhmg-new" "$MASTER_CF"
      ok "master.cf: port 25 now fronted by postscreen (587/465 untouched)"
      HAS_POSTSCREEN=1
    else
      warn "Could not find a plain 'smtp inet … smtpd' line in master.cf — skipping master.cf edit"
      warn "Inspect manually; postscreen main.cf settings below are still applied"
    fi
  fi

  # 2) main.cf — weighted DNSBLs + safe pre-220 tests.
  #    zen.spamhaus.org is the gold standard (*3). dnswl gives NEGATIVE
  #    score so a listed-good sender is whitelisted past the threshold.
  pc_set postscreen_access_list "permit_mynetworks" || true
  pc_set postscreen_greet_action "enforce" || true
  pc_set postscreen_dnsbl_threshold "$DNSBL_THRESHOLD" || true
  pc_set postscreen_dnsbl_action "enforce" || true
  pc_set postscreen_dnsbl_whitelist_threshold "-1" || true
  pc_set postscreen_dnsbl_ttl "1h" || true
  pc_set postscreen_dnsbl_sites \
    "zen.spamhaus.org*3 bl.spamcop.net*2 b.barracudacentral.org*2 dnsbl.sorbs.net*1 list.dnswl.org=127.0.[0..255].0*-2 list.dnswl.org=127.0.[0..255].1*-3 list.dnswl.org=127.0.[0..255].2*-4 list.dnswl.org=127.0.[0..255].3*-5" || true
  ok "main.cf: weighted DNSBL scoring (threshold=$DNSBL_THRESHOLD) + pregreet enforce"

  if [ "$DEEP_PROTOCOL_TESTS" = "1" ]; then
    pc_set postscreen_pipelining_enable "yes" || true
    pc_set postscreen_non_smtp_command_enable "yes" || true
    pc_set postscreen_bare_newline_enable "yes" || true
    pc_set postscreen_dnsbl_whitelist_threshold "-1" || true
    warn "DEEP_PROTOCOL_TESTS on — adds a first-contact retry delay (like greylisting)"
  else
    skip "deep after-220 protocol tests off (set DEEP_PROTOCOL_TESTS=1 to enable)"
  fi

  echo
  warn "NOTE: Spamhaus' free tier requires you query from your OWN resolver"
  warn "(not a public 8.8.8.8-style resolver) and has a daily query cap fine"
  warn "for a single server. Verify named/unbound is the local resolver."

  validate_and_reload
  save_state
}

phase_restrictions() {
  hdr "RESTRICTIONS — harden smtpd HELO / sender / recipient"
  backup_once "$MAIN_CF"

  pc_set smtpd_helo_required "yes" || true

  # pc_harden_list ensures permit_mynetworks + permit_sasl_authenticated lead
  # any list lacking them (so localhost + logged-in users are permitted before
  # the rejects), then APPENDS the reject tokens at the END. Existing entries
  # are never reordered — CWP's reject_unauth_destination + Policyd survive.
  pc_harden_list smtpd_helo_restrictions \
    "reject_invalid_helo_hostname reject_non_fqdn_helo_hostname" || true
  ok "HELO restrictions: invalid/non-FQDN HELO rejected"

  pc_harden_list smtpd_sender_restrictions \
    "reject_non_fqdn_sender reject_unknown_sender_domain" || true
  ok "Sender restrictions: non-FQDN + unknown-domain senders rejected"

  # recipient: reverse-DNS reject (moderate — PTR existence, not strict FCrDNS)
  # appended at the END so it runs after permit + anti-relay rules.
  pc_harden_list smtpd_recipient_restrictions \
    "reject_non_fqdn_recipient reject_unknown_recipient_domain reject_unauth_destination reject_unknown_reverse_client_hostname" || true
  ok "Recipient restrictions: FQDN + reverse-DNS checks (anti-relay preserved)"

  pc_harden_list smtpd_data_restrictions "reject_unauth_pipelining" || true
  ok "Data restrictions: reject_unauth_pipelining (early-talker spambots)"

  validate_and_reload
  save_state
}

phase_greylist() {
  hdr "GREYLIST — postgrey with smart ESP whitelist"
  [ "$HAS_EPEL" = 1 ] || yum install -y epel-release >/dev/null 2>&1 || true
  if [ "$HAS_POSTGREY" != "1" ]; then
    yum install -y postgrey >/dev/null 2>&1 || die "postgrey install failed (check EPEL)"
    ok "postgrey installed"
    HAS_POSTGREY=1
  else
    skip "postgrey already installed"
  fi

  # Smart whitelist: transactional ESPs + big providers MUST never be
  # delayed (order-confirmation emails are time-sensitive for ecommerce).
  # postgrey ships a broad whitelist_clients already; we append extras.
  local wlf=/etc/postfix/postgrey_whitelist_clients.local
  [ -d /etc/postfix ] || mkdir -p /etc/postfix
  cat > "$wlf" <<'WL'
# BH-MAIL-GUARD — never greylist these (transactional ESPs + big mail)
# Matched against client reverse-DNS. Append-only; managed by bh-mail-guard.
google.com
.google.com
.googlemail.com
.outlook.com
.hotmail.com
.protection.outlook.com
.yahoo.com
.yahoodns.net
amazonses.com
.amazonses.com
.sendgrid.net
.mailgun.org
.sparkpostmail.com
.mandrillapp.com
.zoho.com
.mailchimp.com
.postmarkapp.com
.mtasv.net
WL
  # add this server's own domains so internal mail is never delayed
  hostname -d >/dev/null 2>&1 && echo ".$(hostname -d)" >> "$wlf"
  ok "ESP/provider whitelist written: $wlf"

  # Run postgrey in INET mode via a systemd drop-in. On CWP this is far more
  # robust than the unix socket (which silently failed — chroot/SELinux). We
  # run it FOREGROUND as Type=simple (drop -d, clear PIDFile): the stock unit
  # is Type=forking + PIDFile=/var/run/postgrey.pid, and any PID-file path
  # mismatch makes systemd time out + kill it in a restart loop. Foreground
  # sidesteps the whole PID-file dance. postgrey auto-reads both
  # postgrey_whitelist_clients and *.local, so our ESP whitelist is picked up.
  mkdir -p /etc/systemd/system/postgrey.service.d
  cat > /etc/systemd/system/postgrey.service.d/bh-override.conf <<EOF
[Service]
Type=simple
PIDFile=
ExecStart=
ExecStart=/usr/sbin/postgrey --inet=127.0.0.1:$POSTGREY_PORT --delay=$GREYLIST_DELAY --max-age=$GREYLIST_MAX_AGE
Restart=on-failure
RestartSec=2
EOF
  systemctl daemon-reload
  systemctl reset-failed postgrey >/dev/null 2>&1 || true
  systemctl enable postgrey >/dev/null 2>&1 || true
  systemctl restart postgrey 2>/dev/null || systemctl start postgrey 2>/dev/null || true
  sleep 2
  if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$POSTGREY_PORT\b"; then
    ok "postgrey listening on 127.0.0.1:$POSTGREY_PORT (delay=${GREYLIST_DELAY}s, max-age=${GREYLIST_MAX_AGE}d)"
  else
    warn "postgrey not listening yet — check: journalctl -u postgrey | tail"
    warn "(mail still flows — policy service is fail-open, set below)"
  fi

  backup_once "$MAIN_CF"
  # Fail-open: an unreachable policy service returns DUNNO instead of
  # 451-deferring legit mail. Same philosophy as milter_default_action=accept.
  pc_set smtpd_policy_service_default_action "DUNNO" || true
  # Drop any stale unix-socket policy line from an earlier run (we use inet now).
  pc_strip_token smtpd_recipient_restrictions "check_policy_service unix:postgrey/socket"
  # Wire into recipient restrictions at the END (after anti-relay). Always inet.
  # pc_append_one keeps 'check_policy_service inet:...' as ONE entry.
  pc_append_one smtpd_recipient_restrictions "check_policy_service inet:127.0.0.1:$POSTGREY_PORT" || true
  ok "greylisting wired (inet:127.0.0.1:$POSTGREY_PORT) — fail-open enabled"

  validate_and_reload
  save_state
}

phase_dmarc() {
  hdr "DMARC — opendmarc inbound validation (mark-only by default)"
  [ "$HAS_EPEL" = 1 ] || yum install -y epel-release >/dev/null 2>&1 || true
  if [ "$HAS_OPENDMARC" != "1" ]; then
    yum install -y opendmarc >/dev/null 2>&1 || die "opendmarc install failed (check EPEL)"
    ok "opendmarc installed"
    HAS_OPENDMARC=1
  else
    skip "opendmarc already installed"
  fi

  local conf=/etc/opendmarc.conf
  backup_once "$conf"
  # RejectFailures false = add Authentication-Results header, DON'T reject.
  # SpamAssassin then scores DMARC fails. Safer than hard-reject (avoids
  # bouncing legit senders whose DMARC is misconfigured). Flip with DMARC_REJECT=1.
  local reject="false"; [ "$DMARC_REJECT" = "1" ] && reject="true"
  cat > "$conf" <<EOF
# BH-MAIL-GUARD managed opendmarc config
AuthservID HOSTNAME
PidFile /run/opendmarc/opendmarc.pid
RejectFailures $reject
Syslog true
TrustedAuthservIDs HOSTNAME
Socket inet:$OPENDMARC_PORT@127.0.0.1
UMask 0002
IgnoreAuthenticatedClients true
RequiredHeaders false
SPFSelfValidate true
EOF
  mkdir -p /run/opendmarc 2>/dev/null || true
  chown opendmarc:opendmarc /run/opendmarc 2>/dev/null || true
  systemctl enable opendmarc >/dev/null 2>&1 || true
  systemctl restart opendmarc 2>/dev/null || systemctl start opendmarc 2>/dev/null || warn "could not start opendmarc"
  [ "$reject" = "true" ] && warn "DMARC hard-reject ON (p=reject failures bounced)" \
                         || ok "opendmarc mark-only (SA scores failures) — port $OPENDMARC_PORT"

  # APPEND to smtpd_milters (do NOT clobber opendkim's milter)
  backup_once "$MAIN_CF"
  pc_append_one smtpd_milters "inet:127.0.0.1:$OPENDMARC_PORT" || true
  pc_append_one non_smtpd_milters "inet:127.0.0.1:$OPENDMARC_PORT" || true
  pc_set milter_default_action "accept" || true   # never block mail if milter is down
  ok "opendmarc milter appended (opendkim preserved); fail-open if milter down"

  validate_and_reload
  save_state
}

phase_sa_tune() {
  hdr "SA-TUNE — SpamAssassin Bayes + KAM rules + network tests"
  [ "$HAS_SA" = 1 ] || { warn "SpamAssassin not detected — skipping"; return 0; }
  mkdir -p "$SA_DIR"
  backup_once "$SA_CF"

  cat > "$SA_CF" <<'SACF'
# BH-MAIL-GUARD — SpamAssassin tuning (managed; edits here are overwritten)
# ── Bayes: learn from mail flow so the filter adapts to YOUR spam ──
use_bayes               1
bayes_auto_learn        1
bayes_auto_learn_threshold_nonspam  0.1
bayes_auto_learn_threshold_spam     8.0

# ── Network tests: DNSBLs, Razor, Pyzor, DCC (catch "clever" content) ──
skip_rbl_checks         0
use_razor2              1
use_pyzor               1
dns_available           yes

# ── Score tuning: lean harder on auth + spoofing signals ──
score BAYES_99          4.5
score BAYES_999         5.0
score SPF_FAIL          2.0
score SPF_SOFTFAIL      1.0
score DKIM_ADSP_DISCARD 3.0
score RDNS_NONE         1.5
score FROM_SUSPICIOUS_NTLD 2.0

# ── DMARC: opendmarc adds Authentication-Results; score the failures ──
header   BHMG_DMARC_FAIL  Authentication-Results =~ /dmarc=fail/
describe BHMG_DMARC_FAIL  Inbound message failed sender's DMARC policy
score    BHMG_DMARC_FAIL  3.5

# ── Tag + threshold ──
required_score          5.0
rewrite_header Subject  [SPAM]
SACF
  ok "wrote $SA_CF (Bayes + network tests + DMARC scoring)"

  # Enable the HashBL plugin if SpamAssassin ships it (a commented stub is
  # present) but it's disabled — CWP ships it commented in v342.pre. Without
  # it, KAM's hashbl rules throw "unknown eval check_hashbl_emails" lint
  # warnings and don't fire. We ONLY uncomment an existing stub (never add a
  # loadplugin for a missing module, which would break lint). HashBL does DNS
  # lookups — now useful fleet-wide since every box has a local resolver.
  if [ "${ENABLE_HASHBL:-1}" = "1" ] && [ -d "$SA_DIR" ]; then
    if ! grep -rqsE '^[[:space:]]*loadplugin[[:space:]]+\S*HashBL' "$SA_DIR"/*.pre 2>/dev/null \
       && grep -rlqsE '^[[:space:]]*#[[:space:]]*loadplugin[[:space:]]+\S*HashBL' "$SA_DIR"/*.pre 2>/dev/null; then
      sed -i -E 's|^([[:space:]]*)#[[:space:]]*(loadplugin[[:space:]]+\S*HashBL)|\1\2|' "$SA_DIR"/*.pre
      ok "enabled HashBL plugin (clears hashbl lint warnings + activates hashbl rules)"
    else
      skip "HashBL plugin already enabled or no stub present"
    fi
  fi

  # KAM ruleset channel (high-quality community rules, big accuracy boost).
  # Robust + self-diagnosing: validate the downloaded key is a real PGP block
  # (a 404 HTML page silently breaks --import), capture real errors, and treat
  # sa-update exit 1 as SUCCESS — it means "no new rules", not an error
  # (only exit >=4 is a real failure; 1 = up-to-date, 0 = updated).
  if [ "$INSTALL_KAM" = "1" ]; then
    if command -v sa-update >/dev/null 2>&1; then
      local kamkey=/tmp/bhmg-kam.key kam_ok=0
      # McGrail renamed the key file in 2026 (old MCGRAIL-GPG.KEY now 404).
      local kamurl="https://mcgrail.com/downloads/kam.sa-channels.mcgrail.com.key"
      # timeouts are essential — without them a slow/stalled route to mcgrail.com
      # hangs the whole deploy (hit on s4). curl: 10s connect / 60s total.
      curl -fsSL --connect-timeout 10 --max-time 60 --retry 2 "$kamurl" -o "$kamkey" 2>/tmp/bhmg-kam.err \
        || wget -q --timeout=20 --tries=2 -O "$kamkey" "$kamurl" 2>>/tmp/bhmg-kam.err || true
      if grep -q 'BEGIN PGP' "$kamkey" 2>/dev/null; then
        if sa-update --import "$kamkey" 2>/tmp/bhmg-kam.err; then
          ok "imported KAM GPG key (24C063D8)"; kam_ok=1
        else
          warn "KAM key import failed: $(tail -1 /tmp/bhmg-kam.err 2>/dev/null)"
        fi
      else
        warn "KAM key download did not return a PGP key (URL blocked/404?) — skipping KAM channel"
        warn "  first line got: $(head -1 "$kamkey" 2>/dev/null | cut -c1-60)"
      fi
      if [ "$kam_ok" = "1" ]; then
        local rc=0
        # `|| rc=$?` keeps set -e from aborting on the expected exit 1.
        # `timeout 180` stops a slow channel mirror from hanging the deploy
        # (rc=124 = timed out → reported as a failure, deploy continues).
        timeout 180 sa-update --gpgkey 24C063D8 --channel kam.sa-channels.mcgrail.com --channel updates.spamassassin.org 2>/tmp/bhmg-kam.err || rc=$?
        if [ "$rc" -le 1 ]; then ok "sa-update ran KAM + default channels (rc=$rc: $([ "$rc" = 0 ] && echo updated || echo up-to-date))"
        elif [ "$rc" = 124 ]; then warn "sa-update timed out (slow channel mirror) — KAM skipped this run, retry later"
        else err "sa-update failed (rc=$rc):"; sed 's/^/      /' /tmp/bhmg-kam.err >&2 || true; fi
      fi
    else
      warn "sa-update not found — skipping KAM channel"
    fi
  fi

  # validate the SA ruleset compiles before restarting consumers
  if command -v spamassassin >/dev/null 2>&1; then
    if spamassassin --lint 2>/tmp/bhmg-salint.err; then
      ok "spamassassin --lint passed"
    else
      err "spamassassin --lint FAILED:"; sed 's/^/      /' /tmp/bhmg-salint.err >&2 || true
      warn "Leaving $SA_CF in place but NOT restarting amavis — fix lint errors first"
      return 0
    fi
  fi

  # restart whatever actually runs SA — then VERIFY amavis actually came up.
  # On IPv6-disabled CWP boxes, amavis 2.13 tries to bind ::1:10024, fails
  # ("Cannot assign requested address"), and stays down — postfix then quietly
  # queues all inbound mail. Don't report success blindly (we used to).
  systemctl restart spamassassin 2>/dev/null || true
  if systemctl list-unit-files 2>/dev/null | grep -q '^amavisd'; then
    systemctl restart amavisd 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet amavisd; then
      ok "restarted SpamAssassin + amavisd (amavisd active, listening 10024)"
    else
      err "amavisd FAILED to start — inbound mail will queue until fixed."
      warn "If maillog shows \"Can't ... port 10024 on ::1 [Cannot assign requested address]\","
      warn "this box has IPv6 off and amavis 2.13 can't bind ::1. Fix in /etc/amavisd/amavisd.conf:"
      warn "    \$inet_socket_bind = '127.0.0.1';"
      warn "    \$inet_socket_port = 10024;"
      warn "then:  systemctl restart amavisd && postqueue -f"
    fi
  else
    systemctl restart amavis 2>/dev/null || true
    ok "restarted SpamAssassin/Amavis consumers"
  fi
  echo
  say "Tip: train Bayes faster by feeding known spam/ham:"
  say "  sa-learn --spam /path/to/Junk    # per-mailbox spam folders"
  say "  sa-learn --ham  /path/to/INBOX"
  save_state
}

# ─────────── self-heal cron (defeats CWP Rebuild Postfix) ───────────
save_state() {
  mkdir -p "$STATE_DIR"
  cat > "$STATE_DIR/desired.env" <<EOF
# Written by bh-mail-guard.sh $RUNSTAMP — read by the heal cron.
DNSBL_THRESHOLD=$DNSBL_THRESHOLD
DEEP_PROTOCOL_TESTS=$DEEP_PROTOCOL_TESTS
GREYLIST_DELAY=$GREYLIST_DELAY
GREYLIST_MAX_AGE=$GREYLIST_MAX_AGE
DMARC_REJECT=$DMARC_REJECT
OPENDMARC_PORT=$OPENDMARC_PORT
POSTGREY_PORT=$POSTGREY_PORT
HAS_POSTGREY=$HAS_POSTGREY
HAS_OPENDMARC=$HAS_OPENDMARC
EOF
}

phase_heal_install() {
  hdr "HEAL-INSTALL — re-assert config after CWP rebuilds (every 10 min)"
  mkdir -p "$STATE_DIR"
  save_state
  local heal=/usr/local/sbin/bh-mail-guard-heal.sh
  cat > "$heal" <<'HEAL'
#!/bin/bash
# BH-MAIL-GUARD-HEAL — every 10 min, re-assert BH anti-spam settings.
# CWP's "Rebuild Postfix Configuration" regenerates main.cf/master.cf and
# wipes our changes; this restores them. Validates with `postfix check`
# before reloading; reloads ONLY when something actually changed.
set -e
STATE_DIR=/var/lib/bh-mail-guard
ENVF="$STATE_DIR/desired.env"
[ -f "$ENVF" ] || exit 0
. "$ENVF"
POSTCONF="$(command -v postconf || echo /usr/sbin/postconf)"
MAIN_CF=/etc/postfix/main.cf
MASTER_CF=/etc/postfix/master.cf
LOG=/var/log/bh-mail-guard.log
CHANGED=0
log(){ echo "[$(date '+%F %T')] heal: $*" >> "$LOG"; }

pc_get(){ "$POSTCONF" -h "$1" 2>/dev/null; }
pc_set(){ local k="$1" v="$2"; [ "$(pc_get "$k")" = "$v" ] || { "$POSTCONF" -e "$k=$v"; CHANGED=1; log "set $k"; }; }
# Split on COMMA only — Postfix entries like 'check_policy_service inet:...'
# contain an inner space that must NOT be treated as a separator.
_ent(){ pc_get "$1" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' || true; }
_wr(){ local k="$1" j; j="$(grep -v '^$' | paste -sd, - | sed 's/,/, /g')"; "$POSTCONF" -e "$k=$j"; CHANGED=1; log "set $k"; }
pc_one(){ # append ONE (possibly multi-word) entry at END iff absent
  local key="$1" entry="$2" e; e="$(_ent "$key")"
  printf '%s\n' "$e" | grep -qxF "$entry" && return 0
  printf '%s\n%s\n' "$e" "$entry" | _wr "$key"
}
pc_hard(){ # ensure permit_* lead a permit-less list, append single-word rejects
  local key="$1" toks="$2" e t chg=0; e="$(_ent "$key")"
  if ! printf '%s\n' "$e" | grep -qxE 'permit_mynetworks|permit_sasl_authenticated'; then
    e="$(printf 'permit_mynetworks\npermit_sasl_authenticated\n%s' "$e")"; chg=1; fi
  for t in $toks; do printf '%s\n' "$e" | grep -qxF "$t" || { e="$(printf '%s\n%s' "$e" "$t")"; chg=1; }; done
  [ "$chg" = 1 ] && printf '%s\n' "$e" | _wr "$key"
}

# master.cf postscreen block
if ! grep -qE '^[[:space:]]*[^#].*postscreen' "$MASTER_CF"; then
  if grep -qE '^smtp[[:space:]]+inet[[:space:]].*[[:space:]]smtpd([[:space:]]|$)' "$MASTER_CF"; then
    cp -a "$MASTER_CF" "${MASTER_CF}.bh-heal-$(date +%s)"
    awk 'BEGIN{d=0} /^smtp[ \t]+inet[ \t]+.*[ \t]smtpd([ \t]|$)/&&!d{print "# BH-MAIL-GUARD-POSTSCREEN";print "smtp      inet  n       -       n       -       1       postscreen";print "smtpd     pass  -       -       n       -       -       smtpd";print "dnsblog   unix  -       -       n       -       0       dnsblog";print "tlsproxy  unix  -       -       n       -       0       tlsproxy";print "# END BH-MAIL-GUARD-POSTSCREEN";d=1;next}{print}' "$MASTER_CF" > "${MASTER_CF}.hn" && mv "${MASTER_CF}.hn" "$MASTER_CF"
    CHANGED=1; log "re-asserted postscreen in master.cf"
  fi
fi

# main.cf postscreen scoring
pc_set postscreen_access_list permit_mynetworks
pc_set postscreen_greet_action enforce
pc_set postscreen_dnsbl_threshold "${DNSBL_THRESHOLD:-3}"
pc_set postscreen_dnsbl_action enforce
pc_set postscreen_dnsbl_whitelist_threshold -1
pc_set postscreen_dnsbl_sites "zen.spamhaus.org*3 bl.spamcop.net*2 b.barracudacentral.org*2 dnsbl.sorbs.net*1 list.dnswl.org=127.0.[0..255].0*-2 list.dnswl.org=127.0.[0..255].1*-3 list.dnswl.org=127.0.[0..255].2*-4 list.dnswl.org=127.0.[0..255].3*-5"

# restrictions
pc_set smtpd_helo_required yes
pc_hard smtpd_helo_restrictions "reject_invalid_helo_hostname reject_non_fqdn_helo_hostname"
pc_hard smtpd_sender_restrictions "reject_non_fqdn_sender reject_unknown_sender_domain"
pc_hard smtpd_recipient_restrictions "reject_non_fqdn_recipient reject_unknown_recipient_domain reject_unauth_destination reject_unknown_reverse_client_hostname"
pc_hard smtpd_data_restrictions "reject_unauth_pipelining"

# greylist policy service (always inet; fail-open so a dead service never defers mail)
if [ "${HAS_POSTGREY:-0}" = "1" ]; then
  PGP="${POSTGREY_PORT:-10023}"
  pc_set smtpd_policy_service_default_action DUNNO
  # strip any stale unix-socket entry a CWP rebuild may have re-templated
  if pc_get smtpd_recipient_restrictions | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -qxF "check_policy_service unix:postgrey/socket"; then
    NL="$(pc_get smtpd_recipient_restrictions | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -vxF "check_policy_service unix:postgrey/socket" | paste -sd, - | sed 's/,/, /g')"
    "$POSTCONF" -e "smtpd_recipient_restrictions=$NL"; CHANGED=1; log "stripped stale unix postgrey socket"
  fi
  pc_one smtpd_recipient_restrictions "check_policy_service inet:127.0.0.1:$PGP"
fi

# dmarc milter
if [ "${HAS_OPENDMARC:-0}" = "1" ]; then
  pc_one smtpd_milters "inet:127.0.0.1:${OPENDMARC_PORT:-8893}"
  pc_one non_smtpd_milters "inet:127.0.0.1:${OPENDMARC_PORT:-8893}"
  pc_set milter_default_action accept
fi

if [ "$CHANGED" = "1" ]; then
  if postfix check 2>/tmp/bhmg-heal-check.err; then
    systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null || true
    log "config drifted (CWP rebuild?) — re-asserted + reloaded"
  else
    log "WARN: postfix check failed during heal — NOT reloading"
  fi
fi
HEAL
  chmod +x "$heal"
  cat > /etc/cron.d/bh-mail-guard-heal <<'CRON'
# BH-MAIL-GUARD-HEAL — re-asserts anti-spam config after CWP rebuilds. Keep.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
*/10 * * * * root /usr/local/sbin/bh-mail-guard-heal.sh >/dev/null 2>&1
# END BH-MAIL-GUARD-HEAL
CRON
  chmod 644 /etc/cron.d/bh-mail-guard-heal
  ok "heal cron installed: /usr/local/sbin/bh-mail-guard-heal.sh (every 10 min)"
  ok "survives CWP 'Rebuild Postfix Configuration' — re-asserts within 10 min"
}

phase_status() {
  hdr "STATUS — live anti-spam counters"
  local ml=/var/log/maillog
  [ -f "$ml" ] || ml=/var/log/mail.log
  if [ ! -f "$ml" ]; then warn "no maillog found"; return 0; fi
  say "Reading $ml (today)…"
  local today; today="$(date '+%b %e')"
  # grep -c already prints 0 on no match — `|| true` swallows the exit-1 so we
  # don't double-print a second 0 (the cosmetic v1.0.2 bug). Use -E patterns.
  cnt() { grep -cE "$1" "$ml" 2>/dev/null || true; }
  echo
  printf "  %-34s %s\n" "postscreen DNSBL rejects:"    "$(cnt 'postscreen.*blocked using|postscreen.*DNSBL rank [0-9]+ for.*reject')"
  printf "  %-34s %s\n" "postscreen pregreet rejects:" "$(cnt 'postscreen.*PREGREET')"
  printf "  %-34s %s\n" "HELO/FQDN rejects:"           "$(cnt 'reject.*(helo|HELO|non-FQDN|FQDN)')"
  printf "  %-34s %s\n" "unknown-domain rejects:"      "$(cnt '(Sender|Recipient) address rejected.*Domain not found')"
  printf "  %-34s %s\n" "reverse-DNS rejects:"         "$(cnt 'reject.*Client host rejected.*cannot find')"
  printf "  %-34s %s\n" "greylist deferrals (451):"    "$(cnt 'Greylisting in action|postgrey')"
  printf "  %-34s %s\n" "SpamAssassin tagged spam:"    "$(cnt 'Passed SPAM|identified as spam')"
  printf "  %-34s %s\n" "amavis clean passes:"         "$(cnt 'Passed CLEAN')"
  echo
  say "Services:"
  for s in postfix postgrey opendmarc spamassassin amavisd; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^$s"; then
      printf "    %-14s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo n/a)"
    fi
  done
  echo
  say "Top 10 rejected client IPs today (all reject layers):"
  grep "$today" "$ml" 2>/dev/null | grep -E 'reject:|blocked using|PREGREET' \
    | grep -oE '\[[0-9]{1,3}(\.[0-9]{1,3}){3}\]' | tr -d '[]' \
    | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /' || true
  echo
  say "Heal cron: $([ -f /etc/cron.d/bh-mail-guard-heal ] && echo "${c_ok}installed${c_off}" || echo "not installed")"
}

phase_all() {
  phase_postscreen
  phase_restrictions
  phase_greylist
  phase_dmarc
  phase_sa_tune
  phase_heal_install
  hdr "DONE — full BH Mail Guard deployment"
  say "Layers active: postscreen → restrictions → greylist → dmarc → SA-tune"
  say "Self-heal cron guards against CWP 'Rebuild Postfix'."
  echo
  say "${c_ok}Watch it work:${c_off}"
  say "  tail -f /var/log/maillog | grep -E 'postscreen|reject|postgrey'"
  say "  bash $0 status          # counters after a few hours"
  echo
  say "${c_warn}Rollback (this run):${c_off}"
  say "  cp -a ${MAIN_CF}.bh-bak-${RUNSTAMP} $MAIN_CF"
  say "  cp -a ${MASTER_CF}.bh-bak-${RUNSTAMP} $MASTER_CF"
  say "  rm -f /etc/cron.d/bh-mail-guard-heal"
  say "  systemctl restart postfix"
}

# ════════════════════════════ MAIN ════════════════════════════
echo "╔══════════════════════════════════════════════╗"
echo "║   BH Mail Guard — CWP/Postfix anti-spam v1.0   ║"
echo "╚══════════════════════════════════════════════╝"
detect_env

case "$PHASE" in
  detect)        phase_detect ;;
  postscreen)    phase_postscreen ;;
  restrictions)  phase_restrictions ;;
  greylist)      phase_greylist ;;
  dmarc)         phase_dmarc ;;
  sa-tune)       phase_sa_tune ;;
  heal-install)  phase_heal_install ;;
  status)        phase_status ;;
  all)           phase_all ;;
  "")
    phase_detect
    echo
    if [ "$INTERACTIVE" = "1" ]; then
      ask_yn "Run the FULL deployment now (all layers)?" "n"
      [ "$REPLY" = "1" ] && { echo; phase_all; } || say "No changes made. Run a phase explicitly, e.g.: bash $0 all"
    else
      say "No phase given. Run:  bash $0 all   (or a single phase)"
    fi
    ;;
  *) die "Unknown phase '$PHASE'. Phases: detect postscreen restrictions greylist dmarc sa-tune heal-install status all" ;;
esac
