# `drupal-installer-scanner`

Detection-only triage for `CVE-2026-132165`, the `Drupal core` installer flaw (`SA-CORE-2026-017`) that lets an unauthenticated visitor try to reinstall a site that is already installed — and take it over. `Drupal` disclosed it on `18 Nov 2026`, rated it `Highly critical 20/25`, and later added that it was exploited on live sites as early as `19 Nov 2026 19:00 UTC`. `CISA` added it to its `Known Exploited Vulnerabilities` catalog on `24 Nov 2026`, due `27 Nov 2026`. Grades your core version against the fixed releases, reads the version your site already discloses, and probes `/core/install.php` with one plain `GET` to see whether the installer answers "already installed" or serves an install form. Nothing here sends a payload, submits a form, or `POST`s anything.

`v1.1.0` covers the follow-up flaw too: on `25 Nov 2026` `Drupal` published `SA-CORE-2026-019` (`CVE-2026-136716`, `Highly critical 21/25`), because sites in unusual or incomplete install states stayed open to the same installer takeover after the first fix — including production sites — and it is being exploited in the wild. The first-wave releases (`10.6.22`, `11.3.22`, `11.4.13`) are not enough. The fixed releases are now `10.6.23`, `11.3.23` and `11.4.14`, and `update.php` must be run after updating.

## `What it checks`

* `CVE-2026-132165` — `Drupal core` ships with `core/install.php`, and it stays on the site after installation. Under specific conditions, an anonymous visitor can use that installer to try to reinstall a finished site, which can lead to site takeover or remote code execution. `CVSS 3.1 9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) per `Tenable`, citing `Mitre`/`NVD`; a `CVSS 4.0` score of `9.2` is also in circulation, and `NVD` had not published a record of its own at the time of writing, so the `9.8` is the `Tenable` figure and the `9.2` is the second opinion — both agree it is critical, they disagree on the decimal. `CWE-94` (code injection) per the bulletin; some trackers also map it to `CWE-284` / `CWE-502`. Found by `Anthropic's OSS Scanner` (`ANT-2026-GMRPK0BU`).

Fixed versions, per the vendor advisories `SA-CORE-2026-017` and `SA-CORE-2026-019` (primary sources):

| `Branch` | `Upgrade to` |
| --- | --- |
| `Drupal 10.6.x` | `10.6.23` (or later) |
| `Drupal 11.3.x` | `11.3.23` (or later) |
| `Drupal 11.4.x` | `11.4.14` (or later) |

The first-wave fix (`10.6.22`, `11.3.22`, `11.4.13`) closed `CVE-2026-132165` but left sites open to `CVE-2026-136716` — this scanner grades those versions vulnerable and says why. After updating, run `update.php`: an update hook must run to repair existing sites in the vulnerable state, and the fix is not complete until it has. Sites that had already secured the installer are not vulnerable to the follow-up flaw.

`Drupal 11.2.x` and below, `10.5.x` and below, and `Drupal 8` and `9` are end of life and get no fix on those branches. `Drupal 11.5 beta` and `12.0` are listed as affected in the `16 November` PSA with no fixed release on those lines yet — this scanner grades them vulnerable and says so.

* The companion flaw, same releases, same fix. `CVE-2026-132166` (`SA-CORE-2026-018`, `Moderately critical 14/25`) is a gadget chain in `Drupal core` classes. It is not directly exploitable — it needs a separate bug that unserializes attacker input, and administrator access — so this scanner flags it in the same verdict rather than pretending it is a separate problem.

If you cannot update yet, block the installer. The advisory says to deny `/core/install.php` at the web server, with a prefix rule, not an exact-match rule — an exact-match rule lets `/core/install.php/foo` through. Keeping the web server from writing to or changing permissions on `settings.php` mitigates some, but not all, exploit paths.

## `Usage`

```bash
# grade a version string
python3 drupal_installer_scanner.py --version "11.4.12"
python3 drupal_installer_scanner.py --version "11.4.14"

# a live site: public reads only — CHANGELOG.txt, X-Generator, one GET of /core/install.php
python3 drupal_installer_scanner.py --url https://example.com

# the box that runs the site (web root or project root)
python3 drupal_installer_scanner.py --local-dir /var/www/html

# hunt the access logs for installer requests (POSTs are attack probes)
python3 drupal_installer_scanner.py --version "11.4.12" --access-log /var/log/nginx/access.log

# hunt a Drupal tree for PHP files under sites/*/files (uploaded shells)
python3 drupal_installer_scanner.py --version "11.4.12" --ioc-dir /var/www/html

# a whole fleet at once
python3 drupal_installer_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 drupal_installer_scanner.py --version "11.4.12" --json
python3 drupal_installer_scanner.py --list
```

`--url` `GET`s `/CHANGELOG.txt` (then `/core/CHANGELOG.txt`), reads the `X-Generator` header off the homepage, and `GET`s `/core/install.php`. `--local-dir` reads the version from `CHANGELOG.txt`, `core/lib/Drupal.php` (`const VERSION`), or `composer.lock` (`drupal/core` package), in that order. `--access-log` greps for `install.php` requests and marks `POST`s. `--ioc-dir` walks a tree for `.php` files under any `sites/*/files` directory — the files directory is for uploads, never for executable code.

Exit codes: `0` patched / no hits, `1` vulnerable or hits found, `2` unknown, `3` usage error.

## `Traps`

* The stuck-state trap. The exploit needs a finished site whose stored `install_task` state is something other than `done` while `install_time` is set. That state is uncommon — a normal site that finished the installer and recorded `"done"` does not take this path. So a vulnerable version answering `"already installed"` is not proof of safety, it only proves the installer is not resumable right now. The version verdict still rules, and the installer probe can only add certainty in one direction: a resumable installer is the exploitable condition itself. Check your own state with `drush state:get install_task` and `drush state:get install_time`.
* The `CHANGELOG.txt` trap. Some sites remove `CHANGELOG.txt` as hardening, and some never had it at the web root. Then `--url` falls back to the `X-Generator` header, which only carries the major version (`Drupal 11`) — not enough to grade a branch. Grade the version locally with `--local-dir` instead.
* The exact-match block trap. `Drupal's` updated securing-the-installer documentation warns against an exact-match rule in `Nginx`, because servers that send any URL containing the path still route it to the installer. `/core/install.php/foo` slipped past an exact-match block in testing. Use a prefix rule.
* The `settings.php` trap. Keeping the web server from writing to or changing permissions on `settings.php` mitigates some exploit paths, not all of them. The lab path does not rewrite `settings.php` at all — the account form still runs when the settings are already valid. Do not treat read-only `settings.php` as a fix.
* The first-wave-fix trap. `10.6.22`, `11.3.22` and `11.4.13` fixed `CVE-2026-132165`, and a scanner built on `18 Nov 2026` would have called them patched. `SA-CORE-2026-019` (`25 Nov 2026`) showed those releases stay open to `CVE-2026-136716` in unusual or incomplete install states, and it is being exploited in the wild. If you updated on `18 Nov` and stopped there, you are not done: update again to `10.6.23`, `11.3.23` or `11.4.14` and run `update.php`.
* The patch-is-not-enough trap. Patching closes the hole, it does not undo a break-in. This is unauthenticated takeover with confirmed exploitation on live sites, so a vulnerable install may already be owned. Patch, then check whether user 1's name, email or password changed after `19 Nov 2026`, review `watchdog` for installer activity, and look for new `PHP` files and modules. `--access-log` checks the installer requests for you, `--ioc-dir` checks the uploaded-`PHP` sign, and no hits in the places checked is not a clean bill — attackers clean up, and logs rotate.
* The `NVD` lag trap. `NVD` had not published a record for this `CVE` at the time of writing, and some trackers still show "awaiting analysis". That is a tracker lag, not a disagreement about the flaw — the vendor advisory, the `KEV` listing and the exploitation report are all primary sources and all agree.

## `Sources`

* `Drupal` security advisory `SA-CORE-2026-017` (`18 Nov 2026`, primary source for the affected range `<10.6.22 || >=11.0.0 <11.3.22 || >=11.4.0 <11.4.13`, the fixed releases, the `20/25` rating, and the exploitation report "as early as `2026-11-19 19:00 UTC`")
* `Drupal` security advisory `SA-CORE-2026-019` (`25 Nov 2026`, primary source for the follow-up flaw `CVE-2026-136716`: affected `<10.6.23 || >=11.0.0 <11.3.23 || >=11.4.0 <11.4.14`, the `21/25` rating, "being exploited in the wild", the fixed releases `10.6.23` / `11.3.23` / `11.4.14`, and the `update.php` requirement; no `CVSS` score yet)
* `Drupal` security advisory `SA-CORE-2026-018` (`18 Nov 2026`, primary source for the companion gadget chain `CVE-2026-132166`, `Moderately critical 14/25`)
* `CISA KEV` catalog (`24 Nov 2026`, added `CVE-2026-132165`, due `27 Nov 2026`; corroborated by the `24 Nov` `KEV` trackers)
* `Tenable` `CVE-2026-132165` page (primary source for the `CVSS 3.1 9.8` vector, citing `Mitre`/`NVD`)
* `Abraxas Labs` `abraxas/drupal-install-takeover` (`20 Nov 2026`, primary source for the lab-proven path: stuck `install_task` + set `install_time`, anonymous `POST /core/install.php` reaches the configure-site form on `11.4.12` and replaces user 1, `11.4.13` answers "Drupal already installed")
* `Drupal core` source, tag `11.4.12` (read directly: `core/lib/Drupal.php` carries `const VERSION = '11.4.12'`)
* The `11.4.13` release diff, as measured by independent write-ups (`25 Nov 2026`): the installer changes are in `core/includes/install.core.inc` — a failed database check now stops the installer, a finished install now refuses to restart, only the first browser can continue (session token), and the installer no longer `chmod()`s `settings.php` by itself

Where sources disagree, this scanner follows the vendor advisory and the `CVE` record and says so. The live disagreements are the `CVSS` decimal (`3.1 9.8` per `Tenable` vs `4.0 9.2` per the bulletin) and the `CWE` mapping (`CWE-94` per the bulletin vs `CWE-284`/`CWE-502` on some trackers) — neither changes any verdict.

## `Related work`

A public exploit lab exists (`abraxas/drupal-install-takeover`, `loopback` only, `POST`s the installer) and `PoC` listings are in circulation. No `nuclei` template for `CVE-2026-132165` exists in `projectdiscovery/nuclei-templates` (checked `25 Nov 2026`), and no dedicated version scanner was found. This tool is the defensive counterpart that covers what a single probe does not: version grading from `CHANGELOG.txt` / `Drupal.php` / `composer.lock` / local installs, exposure and installer-state fingerprinting of a live site from public reads, the companion gadget-chain flaw in the same verdict, and the access-log and uploaded-`PHP` IOC hunts from the published attack — all without sending exploit traffic. No `foxcornlab` scanner covered `Drupal` before this one.

## `Thanks to`

* The `Drupal Security Team` — for the advisory that names the flaw plainly, the same-day fix on all three supported branches, and the updated securing-the-installer documentation that warns about the exact-match block
* `Anthropic's OSS Scanner` — for finding it (`ANT-2026-GMRPK0BU`)
* `Abraxas Labs` — for the `loopback`-only lab that proves the exact shape of the fix, `11.4.12` vs `11.4.13`, instead of leaving defenders to guess at it

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run `Drupal`, update to `10.6.23`, `11.3.23` or `11.4.14` and run `update.php` — then hunt, because patching alone does not evict an attacker who already took over user 1.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
