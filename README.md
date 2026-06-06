# BH Mail Guard

Layered anti-spam hardening for **CWP / Postfix** on AlmaLinux 8 (EL8).
Stops the bulk of spam **before** it ever reaches Amavis/SpamAssassin, so your
content filter only sees the survivors — and uses **behavioral** signals (not
blunt IP blocks) so legit senders aren't collaterally blocked.

> Built for the BiswasHost fleet (`biswashost` main VPS + `s1`–`s4`). Same
> idempotent, config-validated, CWP-rebuild-aware style as `bh-server-ops` and
> `cwp-custom-php`.

## Why your current setup leaks spam

Amavis + SpamAssassin + ClamAV + Policyd + DKIM/SPF + Spamhaus-via-CSF is all
**content filtering** — it runs *after* Postfix has already accepted the
message. Every spam mail costs a full SMTP transaction + ClamAV scan + SA
scoring. CWP's stock Postfix usually does **not** enable `postscreen`, the one
layer that rejects botnets at the front door. That's the gap this closes.

## The layers (front-to-back, cheapest first)

| Phase | Layer | Stops | Delay risk |
|---|---|---|---|
| `postscreen` | postscreen + weighted DNSBLs + pregreet test | ~80% of botnet spam, at connect time | none (pre-220) |
| `restrictions` | HELO/FQDN/unknown-domain rejects | forged/garbage senders | none |
| `greylist` | postgrey + smart ESP whitelist | botnets that never retry | first-mail only; ESPs whitelisted |
| `dmarc` | opendmarc inbound (mark-only) | spoofed-domain spam | none |
| `sa-tune` | SA Bayes + KAM rules + network tests | "clever" content spam | n/a (already last) |

Each layer shrinks the next layer's workload.

## Install

SSH into the mail server as root and clone the repo (no manual file upload):

```bash
cd /root && git clone https://github.com/wpexpertinbd/bh-mail-guard.git
cd bh-mail-guard
```

To pull later updates: `cd /root/bh-mail-guard && git pull`.

## Usage

```bash
# 1. ALWAYS start here — read-only, shows what's missing
bash bh-mail-guard.sh detect

# 2. Full recommended deployment (interactive confirm)
bash bh-mail-guard.sh all

# 3. After a few hours, check the counters
bash bh-mail-guard.sh status
```

One-liner for a clean box (clone + inspect + deploy non-interactively):

```bash
cd /root && git clone https://github.com/wpexpertinbd/bh-mail-guard.git && \
cd bh-mail-guard && bash bh-mail-guard.sh detect && bash bh-mail-guard.sh all -y
```

`-y` skips the interactive confirm — use it for fleet rollout after you've
tested on one box. Run individual phases too: `postscreen`, `restrictions`,
`greylist`, `dmarc`, `sa-tune`, `heal-install`, `status`.

## Companion: `bh-resolver.sh` (makes the DNSBL layer actually work)

Spamhaus and most DNSBLs **refuse queries from big public resolvers**
(`8.8.8.8` / `1.1.1.1`) — they silently return nothing. So if `/etc/resolv.conf`
points at one, postscreen's DNSBL scoring is inert (`postscreen DNSBL rejects`
stays `0`). `bh-resolver.sh` installs a local **unbound** caching resolver so
DNSBL lookups resolve and botnets get rejected at connect time — the cheapest
layer of all.

```bash
bash bh-resolver.sh detect      # read-only: live DNSBL test on the current resolver
bash bh-resolver.sh install     # install unbound + repoint resolv.conf (interactive)
bash bh-resolver.sh status
bash bh-resolver.sh rollback    # restore previous resolver
```

Safety (it's the scariest change on a live box — break the resolver, break
everything):
- Binds unbound to **`127.0.0.53:53`**, never `127.0.0.1` — so it never
  collides with CWP's `named`/BIND on `127.0.0.1:53`.
- **Tests that unbound resolves a normal name AND a Spamhaus test entry BEFORE
  touching `resolv.conf`** — aborts if it can't, so DNS never breaks.
- Backs up `resolv.conf` and keeps your old resolver as a **fallback line**
  (used only if unbound is down).
- `STICKY=1` makes `resolv.conf` immutable (`chattr +i`) so NetworkManager /
  dhclient can't revert it; `rollback` clears it. Default off.

If `detect` shows DNSBL lookups already work on a box, no change is needed there.

### Env toggles

| Var | Default | Effect |
|---|---|---|
| `DEEP_PROTOCOL_TESTS` | `0` | postscreen after-220 tests (extra catch, but adds a retry delay — off to avoid double-delay with greylist) |
| `GREYLIST_DELAY` | `120` | seconds postgrey defers first contact |
| `GREYLIST_MAX_AGE` | `35` | days a triplet stays whitelisted |
| `DMARC_REJECT` | `0` | `1` = hard-reject `p=reject` failures (default = mark only, SA scores it) |
| `INSTALL_KAM` | `1` | add KAM SpamAssassin ruleset channel |
| `DNSBL_THRESHOLD` | `3` | postscreen score needed to reject |

## Safety design

- **Surgical, not destructive.** Restriction + milter lists are *appended to*,
  never overwritten — so CWP's `reject_unauth_destination` (anti-open-relay),
  Policyd (`cluebringer`), and `opendkim`'s milter all survive untouched.
- **`permit_mynetworks` + `permit_sasl_authenticated` lead every list** — so
  localhost and logged-in users are never subject to the new rejects or
  greylisting. Reject rules bite anonymous inbound only.
- **587/465 untouched.** postscreen fronts port 25 only; authenticated
  submission ports are never greeted by it.
- **Validate before reload.** Every change runs `postfix check` (and
  `spamassassin --lint`) before reloading; on failure it refuses to reload and
  points you at the `.bh-bak-<timestamp>` backup.
- **DMARC fail-open.** `milter_default_action = accept` — if opendmarc is down,
  mail still flows.
- **Nothing made immutable.** No `chattr +i` — CWP must stay able to add
  domains / DKIM keys.

## CWP "Rebuild Postfix" survival

CWP's **postfix_manager → Rebuild Postfix Configuration** button regenerates
`main.cf`/`master.cf` and wipes our changes. `heal-install` drops a cron at
`/etc/cron.d/bh-mail-guard-heal` (every 10 min) running
`/usr/local/sbin/bh-mail-guard-heal.sh`, which re-asserts every BH key,
re-inserts the postscreen block, validates with `postfix check`, and reloads
**only if** config actually drifted. So a panel rebuild self-heals within 10
minutes. Desired state lives in `/var/lib/bh-mail-guard/desired.env`.

> Re-run `bash bh-mail-guard.sh all` after any CWP update that you suspect
> reset mail config, or just let the heal cron catch it.

## Notes / gotchas

- **Spamhaus free tier** requires queries from your **own** resolver (not a
  public 8.8.8.8-style resolver) and has a daily query cap that's fine for a
  single server. Confirm `named`/`unbound` is the local resolver.
- **`b.barracudacentral.org`** requires registering your resolver IP with
  Barracuda (free) or it returns nothing — harmless if unregistered, just
  inert. `dnsbl.sorbs.net` is weighted low (`*1`) because it's aggressive.
- **Greylisting + ecommerce:** transactional ESPs (Amazon SES, SendGrid,
  Mailgun, SparkPost, Postmark, Mailchimp) and big providers (Gmail, Outlook,
  Yahoo, Zoho) are whitelisted in `/etc/postfix/postgrey_whitelist_clients.local`
  so order-confirmation mail is never delayed. Add more there as needed.
- **postgrey runs in INET mode** (`127.0.0.1:10023`) via a systemd drop-in at
  `/etc/systemd/system/postgrey.service.d/bh-override.conf` — the unix-socket
  mode silently failed to start on CWP (chroot/SELinux/socket-dir pitfalls).
  Verify with `ss -ltn | grep 10023` and `systemctl is-active postgrey`.
- **Fail-open policy service:** `smtpd_policy_service_default_action = DUNNO`
  is set so that if postgrey (or Policyd) is ever unreachable, mail is accepted
  rather than 451-deferred. Availability over strictness.
- **Train Bayes** for faster accuracy gains:
  `sa-learn --spam /path/to/Junk` and `sa-learn --ham /path/to/INBOX`.

## Rollback

```bash
cp -a /etc/postfix/main.cf.bh-bak-<timestamp>   /etc/postfix/main.cf
cp -a /etc/postfix/master.cf.bh-bak-<timestamp> /etc/postfix/master.cf
rm -f /etc/cron.d/bh-mail-guard-heal
systemctl restart postfix
```

## Deploy checklist

1. `git clone` + `detect` on the target box.
2. Deploy on **one** server first, ideally in a low-traffic window
   (postscreen edits `master.cf` — the riskiest change).
3. `tail -f /var/log/maillog | grep -E 'postscreen|reject|postgrey'` and watch
   for an hour — confirm legit mail flows.
4. `status` after a few hours.
5. Roll to the rest of the fleet: on each box, clone the repo and run
   `bash bh-mail-guard.sh detect && bash bh-mail-guard.sh all -y`.
