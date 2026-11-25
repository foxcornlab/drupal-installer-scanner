#!/usr/bin/env python3
"""Detection-only triage for Drupal core CVE-2026-132165.

Drupal core ships with an `install.php` file for installing Drupal
core, and it stays on the site after installation. Under specific
conditions, an unauthenticated visitor can use that installer to
attempt to reinstall a site that is already installed — and that
can lead to site takeover or remote code execution. The Drupal
Security Team disclosed it as SA-CORE-2026-017 on 18 November 2026,
rated it Highly critical (20/25 after the update: AC:Complex /
A:None / CI:All / II:All / E:Exploit / TD:Uncommon), and later added
that it was exploited on live sites as early as 19 November 2026
19:00 UTC. CISA added CVE-2026-132165 to its Known Exploited
Vulnerabilities catalog on 24 November 2026, due 27 November 2026.
CVSS 3.1 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) per
Tenable, citing Mitre/NVD; a CVSS 4.0 score of 9.2 is also in
circulation. NVD had not published a record of its own at the time
of writing, so the 9.8 is the Tenable figure and the 9.2 is the
second opinion — both agree it is critical, they disagree on the
decimal. The flaw was found by Anthropic's OSS Scanner
(ANT-2026-GMRPK0BU). CWE-94 (code injection) per the bulletin;
some trackers also map it to CWE-284 / CWE-502.

The one lab-proven exploit path, published 20 November 2026 by
Abraxas Labs (`abraxas/drupal-install-takeover`, loopback only):
a finished site whose stored `install_task` state is something
other than `done` while `install_time` is set. On 11.4.12, an
anonymous POST to `/core/install.php` then reaches the
configure-site form and replaces user 1's name, email and
password; on 11.4.13 the same request answers "Drupal already
installed" and user 1 is untouched. The stuck state is uncommon
— a normal site that finished the installer and recorded "done"
does not take this path — and the lab plants the state after a
real install, so a remote bug that creates that state was not
shown, and code execution after the new admin logs in was not
shown either. What the lab does prove is the shape of the fix:
11.4.13 refuses to restart a finished install, full stop.

The fix itself, per the 11.4.13 release diff, changes four things
in the installer (`core/includes/install.core.inc`): a failed
database check now stops the installer instead of carrying on as
if the database were empty; a finished install (install_time set)
now refuses to restart; only the first browser to reach the
installer can continue (session token); and the installer no
longer changes file permissions on `settings.php` by itself.

Detection only. This scanner never sends a payload, never submits
a form, and never POSTs anything. What it does instead is version
grading against the vendor's fixed releases, plus reading the
version your install already discloses (`CHANGELOG.txt`, the
`X-Generator` header, `core/lib/Drupal.php`), plus one plain GET
of `/core/install.php` on a live site to see whether the installer
answers "already installed" or serves an install form, plus
hunting your access logs for installer requests and your files
directories for uploaded PHP. A public exploit lab exists (the
Abraxas repo above) and PoC listings are in circulation; this
tool is the defensive counterpart.

Fixed releases, per the vendor advisory SA-CORE-2026-017
(primary source):

    Drupal 10.6.x -> 10.6.22 (or later)
    Drupal 11.3.x -> 11.3.22 (or later)
    Drupal 11.4.x -> 11.4.13 (or later)

Drupal 11.2.x and below, 10.5.x and below, and Drupal 8 and 9 are
end of life and get no fix on those branches — block the
installer and plan the move. Drupal 11.5 beta and 12.0 are listed
as affected in the 16 November PSA with no fixed release on those
lines yet; this scanner grades them vulnerable and says so.

The same releases also fix a second flaw, CVE-2026-132166
(SA-CORE-2026-018, Moderately critical 14/25): a gadget chain in
Drupal core classes. It is not directly exploitable — it needs a
separate bug that unserializes attacker input, and administrator
access — so this scanner flags it in the same verdict rather than
pretending it is a separate problem.

If you cannot update yet, block the installer: the advisory and
the updated securing-the-installer documentation say to deny
`/core/install.php` at the web server (a prefix rule, not an
exact-match rule — an exact-match rule lets `/core/install.php/foo`
through, because servers that send any URL containing the path
still route it to the installer). Keeping the web server from
writing to or changing permissions on `settings.php` mitigates
some, but not all, exploit paths. Patching alone is not enough if
the site was already hit: check whether user 1's name, email or
password changed after 19 November, review watchdog for installer
activity, and look for new PHP files and modules (`--access-log`
and `--ioc-dir` hunt for the first and the last of those; the
user-1 check needs `drush` or database access and is out of scope
here — `drush state:get install_task` and `drush state:get
install_time` tell you whether your installer is in the stuck
state at all).
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-132165"
CVE_COMPANION = "CVE-2026-132166"
CVSS = "9.8"
CWE = "CWE-94"
PRODUCT = "Drupal core"
ADVISORY = "SA-CORE-2026-017"
CVE_PUBLISHED = "2026-11-18"
FIX_RELEASED = "2026-11-18"
EXPLOITED_SINCE = "2026-11-19 19:00 UTC"
KEV_ADDED = "2026-11-24"
KEV_DUE = "2026-11-27"
INSTALLER_PATH = "/core/install.php"

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

# Fixed release per supported branch: (major, minor) -> minimum patch.
# Branches not listed here have no fix on the line: 11.2.x and older
# 11.x, 10.5.x and older, 8.x, 9.x are end of life; 11.5.x and 12.x
# are listed as affected in the 16 November PSA with no fixed
# release yet. Those grade VULNERABLE with the reason named.
FIXED_PATCH = {
    (10, 6): 22,
    (11, 3): 22,
    (11, 4): 13,
}

# A version token: "11.4.12", "11.4", "11". Extra components and
# suffixes ("11.4.13-dev", "11.5.0-beta1", "v11.4.12") are tolerated;
# grading uses the numeric prefix and the suffix is reported, not
# graded — a -dev build of a fixed branch is graded by its base
# version, which is the honest limit of a version string.
VERSION_TOKEN = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

# What CHANGELOG.txt says, first line: "Drupal 11.4.12, 2026-11-04".
CHANGELOG_VERSION = re.compile(
    r"Drupal\s+(\d+(?:\.\d+){1,2})", re.IGNORECASE)

# core/lib/Drupal.php: const VERSION = '11.4.12';
DRUPAL_PHP_VERSION = re.compile(
    r"const\s+VERSION\s*=\s*['\"](\d+(?:\.\d+){1,2})['\"]")

# X-Generator: "Drupal 11 (https://www.drupal.org)" — major only.
GENERATOR_MAJOR = re.compile(
    r"Drupal\s+(\d+)\s*\(", re.IGNORECASE)

# What a resumable installer serves: the language / profile /
# configure-site forms. Any of these in a GET of /core/install.php
# means the installer is live on a finished-looking site.
INSTALLER_FORM_MARKERS = (
    "choose language",
    "select an installation profile",
    "choose profile",
    "configure site",
    "install_configure_form",
    "set up database",
    "verify requirements",
    "choose a language",
    "select installation profile",
)

# What a finished install (or a fixed installer) answers.
ALREADY_INSTALLED_MARKERS = (
    "already installed",
    "drupal is already installed",
)

MAX_LOG_BYTES = 50 * 1024 * 1024  # per file, so a giant log cannot OOM us


def parse_version(raw):
    """Parse "11.4.12" (or "11.4", "11", "11.4.13-dev") into (11, 4, 12).

    Returns None when the string carries no version token at all.
    Missing components default to 0, so "11.4" means (11, 4, 0).
    """
    if raw is None:
        return None
    match = VERSION_TOKEN.search(str(raw).strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def fmt_version(version):
    """Render a version tuple the way Drupal writes it: 11.4.12."""
    return "%d.%d.%d" % version


def grade(version):
    """Grade a parsed Drupal core version tuple.

    Returns (verdict, detail) with verdict VULNERABLE, FIXED or
    UNKNOWN, following SA-CORE-2026-017 exactly: affected is
    <10.6.22 || >=11.0.0 <11.3.22 || >=11.4.0 <11.4.13. Branches
    with no fix on the line grade VULNERABLE with the reason named
    (end of life, or affected per the PSA with no fixed release
    yet). A major version above 12 has no advisory coverage and
    grades UNKNOWN rather than being guessed at.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"
    major, minor, patch = version

    if major >= 13:
        return "UNKNOWN", (
            "%s is above every branch SA-CORE-2026-017 covers — no "
            "advisory coverage for Drupal %d, check the advisory "
            "before trusting this grade" % (fmt_version(version), major))

    if major == 12:
        return "VULNERABLE", (
            "%s is listed as affected in the 16 November PSA with no "
            "fixed release on the 12.x line yet — block "
            "%s and watch for the 12.x security release"
            % (fmt_version(version), INSTALLER_PATH))

    if major == 11:
        if minor >= 5:
            return "VULNERABLE", (
                "%s is listed as affected in the 16 November PSA "
                "(11.5 beta) with no fixed release on this line yet "
                "— block %s and watch for the security release"
                % (fmt_version(version), INSTALLER_PATH))
        if (major, minor) in FIXED_PATCH:
            fixed = FIXED_PATCH[(major, minor)]
            if patch >= fixed:
                return "FIXED", (
                    "%s is at or above the fixed release %d.%d.%d "
                    "(shipped %s) — the installer refuses to restart "
                    "a finished install"
                    % (fmt_version(version), major, minor, fixed,
                       FIX_RELEASED))
            return "VULNERABLE", (
                "%s is below the fixed release %d.%d.%d — update to "
                "%d.%d.%d or later, and block %s until you do "
                "(exploited on live sites since %s; CISA KEV due %s)"
                % (fmt_version(version), major, minor, fixed,
                   major, minor, fixed, INSTALLER_PATH,
                   EXPLOITED_SINCE, KEV_DUE))
        # 11.0.x, 11.1.x, 11.2.x: below the first fixed branch.
        return "VULNERABLE", (
            "%s is on an end-of-life branch (11.2.x and below get no "
            "security coverage) with no fix — update to a supported "
            "branch (11.4.13, 11.3.22 or 10.6.22), and block %s "
            "until you do" % (fmt_version(version), INSTALLER_PATH))

    if major == 10:
        if minor >= 7:
            return "UNKNOWN", (
                "%s is above every 10.x branch SA-CORE-2026-017 covers "
                "— no advisory coverage for Drupal 10.%d, check the "
                "advisory before trusting this grade"
                % (fmt_version(version), minor))
        if (major, minor) in FIXED_PATCH:
            fixed = FIXED_PATCH[(major, minor)]
            if patch >= fixed:
                return "FIXED", (
                    "%s is at or above the fixed release %d.%d.%d "
                    "(shipped %s) — the installer refuses to restart "
                    "a finished install"
                    % (fmt_version(version), major, minor, fixed,
                       FIX_RELEASED))
            return "VULNERABLE", (
                "%s is below the fixed release %d.%d.%d — update to "
                "%d.%d.%d or later, and block %s until you do "
                "(exploited on live sites since %s; CISA KEV due %s)"
                % (fmt_version(version), major, minor, fixed,
                   major, minor, fixed, INSTALLER_PATH,
                   EXPLOITED_SINCE, KEV_DUE))
        return "VULNERABLE", (
            "%s is on an end-of-life branch (10.5.x and below get no "
            "security coverage) with no fix — update to a supported "
            "branch (10.6.22, 11.3.22 or 11.4.13), and block %s "
            "until you do" % (fmt_version(version), INSTALLER_PATH))

    # Drupal 9, 8, 7 and older: end of life, no fix on any branch.
    return "VULNERABLE", (
        "%s is end of life (Drupal 8 and 9 reached end of life; 7 "
        "and older are long past it) with no fix — update to a "
        "supported branch, and block %s until you do"
        % (fmt_version(version), INSTALLER_PATH))


def version_from_changelog(text):
    """Pull "Drupal 11.4.12" out of a CHANGELOG.txt body."""
    match = CHANGELOG_VERSION.search(text or "")
    if not match:
        return None
    return parse_version(match.group(1))


def version_from_drupal_php(text):
    """Pull const VERSION out of a core/lib/Drupal.php body."""
    match = DRUPAL_PHP_VERSION.search(text or "")
    if not match:
        return None
    return parse_version(match.group(1))


def _unverified_context():
    """Drupal sites in labs often run self-signed certificates; the
    probes only read public pages, so verification is skipped the
    way a browser in a lab does it. Never send credentials over
    this channel — this tool never sends any."""
    return ssl._create_unverified_context()


def fetch(url, timeout=10):
    """Plain GET. Returns (status, headers dict, body, error).

    Status None means the connection itself failed; the error string
    says why. HTTPS uses an unverified context (see above).
    Redirects are not followed, so a 302 is reported as a 302 —
    that matters for the installer probe, where a redirect to the
    front page is a different answer from the installer form.
    """
    headers = {
        "User-Agent": "drupal-installer-scanner/1.0 (detection-only triage)"
    }
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(
        NoRedirectHandler,
        urllib.request.HTTPSHandler(context=_unverified_context()))
    try:
        with opener.open(request, timeout=timeout) as resp:
            return (resp.status, dict(resp.headers),
                    resp.read().decode("utf-8", errors="replace"), None)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers), body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, {}, "", str(exc)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects; report the 3xx as it stands."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify_installer_response(status, body):
    """Classify one GET of /core/install.php.

    Returns (state, note) with state RESUMABLE, REFUSES, BLOCKED,
    ABSENT, REDIRECT or UNKNOWN. RESUMABLE means the installer
    serves an install form on a finished-looking site — the exact
    shape the lab proves is exploitable. REFUSES means the page
    says the site is already installed. The honest limit, stated in
    the note: REFUSES on a vulnerable version does not prove
    safety, it only proves the installer is not resumable right
    now (install_task is "done"); the version verdict still rules.
    """
    lowered = (body or "").lower()
    if status is None:
        return "UNKNOWN", "could not reach the installer"
    if status in (401, 403):
        return "BLOCKED", (
            "%s returned HTTP %d — the installer is blocked, which "
            "is the mitigation the advisory recommends" % (INSTALLER_PATH, status))
    if status == 404:
        return "ABSENT", (
            "%s returned HTTP 404 — the installer is not there "
            "(removed, or this is not a Drupal site)" % INSTALLER_PATH)
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT", (
            "%s redirects (HTTP %d) — the installer is not served "
            "directly here; grade the version, not the redirect"
            % (INSTALLER_PATH, status))
    if status != 200:
        return "UNKNOWN", (
            "%s returned HTTP %d — not a recognisable installer "
            "answer" % (INSTALLER_PATH, status))
    if any(m in lowered for m in ALREADY_INSTALLED_MARKERS):
        return "REFUSES", (
            "the installer answers \"already installed\" — it is not "
            "resumable right now. That does not prove a vulnerable "
            "version safe: a finished site with install_task \"done\" "
            "answers the same way, and only the version verdict "
            "decides")
    if any(m in lowered for m in INSTALLER_FORM_MARKERS):
        return "RESUMABLE", (
            "the installer serves an install form (language / profile "
            "/ configure-site) on this site — the exact shape the "
            "published lab proves is exploitable on a finished site "
            "whose install_task is not \"done\"")
    return "UNKNOWN", (
        "%s returned HTTP 200 but the body matches neither the "
        "\"already installed\" answer nor an install form — check it "
        "by hand" % INSTALLER_PATH)


def probe_url(base_url):
    """Grade a live site from public reads only.

    GETs CHANGELOG.txt (then /core/CHANGELOG.txt), the homepage
    headers for X-Generator, and /core/install.php — all plain GETs,
    no form data, no POST. Returns (verdict, detail, notes list).

    The version verdict rules. The installer probe can only add
    certainty in one direction: a resumable installer on a site
    whose version is vulnerable (or unknown) is the exploitable
    condition itself. A resumable installer on a fixed version is
    reported as a contradiction to check by hand (a fixed installer
    refuses a finished install, so either the version read is stale
    or the install was never finished), and the verdict stays FIXED.
    """
    notes = []
    base = base_url.rstrip("/")
    version = None
    version_source = None

    for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
        status, _headers, body, error = fetch("%s%s" % (base, path))
        if status is None:
            notes.append("could not fetch %s: %s" % (path, error))
            continue
        if status == 200:
            found = version_from_changelog(body)
            if found is not None:
                version = found
                version_source = path
                break
            notes.append("%s returned 200 but carries no Drupal "
                         "version line" % path)
        elif status == 404:
            notes.append("%s is absent (404) — some sites remove it "
                         "as hardening" % path)
        else:
            notes.append("%s returned HTTP %d" % (path, status))

    if version is None:
        status, headers, body, error = fetch(base + "/")
        if status is None:
            notes.append("could not fetch the homepage: %s" % error)
        else:
            generator = headers.get("X-Generator", "") or ""
            match = GENERATOR_MAJOR.search(generator)
            if match:
                major = int(match.group(1))
                notes.append(
                    "X-Generator says Drupal %d — major version only, "
                    "not enough to grade a branch" % major)
                if major <= 9:
                    version = (major, 0, 0)
                    version_source = "X-Generator header (major only)"
                elif major >= 12:
                    version = (major, 0, 0)
                    version_source = "X-Generator header (major only)"
            elif "drupal" in (body or "").lower()[:2000]:
                notes.append("homepage looks like Drupal but discloses "
                             "no version — grade locally instead")

    installer_status, _h, installer_body, installer_error = fetch(
        "%s%s" % (base, INSTALLER_PATH))
    if installer_status is None:
        installer_state, installer_note = (
            "UNKNOWN", "could not reach %s: %s"
            % (INSTALLER_PATH, installer_error))
    else:
        installer_state, installer_note = classify_installer_response(
            installer_status, installer_body)
    notes.append("installer probe: %s" % installer_note)

    if version is not None:
        verdict, detail = grade(version)
        notes.append("version %s read from %s"
                     % (fmt_version(version), version_source))
        if installer_state == "RESUMABLE":
            if verdict == "VULNERABLE":
                detail += (
                    "; and the installer is RESUMABLE — it serves an "
                    "install form on this site, which is the "
                    "exploitable condition itself. Block %s now, then "
                    "update" % INSTALLER_PATH)
            elif verdict == "FIXED":
                notes.append(
                    "contradiction to check by hand: the version "
                    "reads fixed but the installer serves a form. A "
                    "fixed installer refuses a finished install, so "
                    "either the version read is stale or this install "
                    "was never finished")
            else:
                verdict = "VULNERABLE"
                detail = (
                    "the installer is RESUMABLE — it serves an install "
                    "form on this site, which is the exploitable "
                    "condition itself. Block %s now, then grade the "
                    "version locally" % INSTALLER_PATH)
        return verdict, detail, notes

    if installer_state == "RESUMABLE":
        return "VULNERABLE", (
            "the installer is RESUMABLE — %s serves an install form "
            "on this site, which is the exploitable condition itself, "
            "and no version could be read to rule it out. Block %s "
            "now, then grade the version locally"
            % (INSTALLER_PATH, INSTALLER_PATH)), notes
    return "UNKNOWN", (
        "no version could be read (CHANGELOG.txt absent or removed, "
        "no usable X-Generator header) and the installer probe did "
        "not settle it (%s) — grade the version locally with "
        "--local-dir or --version" % installer_state.lower()), notes


def read_local_dir(path):
    """Grade a Drupal install from a directory on this box.

    Accepts the web root (or the project root): tries CHANGELOG.txt,
    then core/lib/Drupal.php (const VERSION), then composer.lock
    (the drupal/core package version). Returns (version tuple or
    None, notes list). The first source that yields a version wins,
    and the note says which one it was.
    """
    target = Path(path)
    if not target.exists():
        return None, ["local path %s does not exist" % path]
    root = target if target.is_dir() else target.parent

    changelog = root / "CHANGELOG.txt"
    if changelog.is_file():
        try:
            found = version_from_changelog(
                changelog.read_text(errors="replace"))
        except OSError as exc:
            return None, ["cannot read %s: %s" % (changelog, exc)]
        if found is not None:
            return found, ["version %s read from CHANGELOG.txt"
                           % fmt_version(found)]

    drupal_php = root / "core" / "lib" / "Drupal.php"
    if drupal_php.is_file():
        try:
            found = version_from_drupal_php(
                drupal_php.read_text(errors="replace"))
        except OSError as exc:
            return None, ["cannot read %s: %s" % (drupal_php, exc)]
        if found is not None:
            return found, ["version %s read from core/lib/Drupal.php "
                           "(const VERSION)" % fmt_version(found)]

    lock = root / "composer.lock"
    if lock.is_file():
        try:
            data = json.loads(lock.read_text(errors="replace"))
        except (OSError, ValueError) as exc:
            return None, ["cannot read composer.lock: %s" % exc]
        for section in ("packages", "packages-dev"):
            for package in data.get(section, []):
                if package.get("name") == "drupal/core":
                    found = parse_version(package.get("version", ""))
                    if found is not None:
                        return found, [
                            "version %s read from composer.lock "
                            "(drupal/core package)" % fmt_version(found)]
                    return None, [
                        "composer.lock lists drupal/core %r, which is "
                        "not parseable"
                        % package.get("version", "")]
        return None, ["composer.lock lists no drupal/core package"]

    return None, [
        "no Drupal version found under %s — looked for CHANGELOG.txt, "
        "core/lib/Drupal.php and composer.lock; pass the web root or "
        "the project root" % path]


def scan_access_log(path):
    """Grep access logs for requests to the Drupal installer.

    Accepts one log file or a directory of .log files. Flags every
    line mentioning core/install.php (or install.php with path-info,
    /core/install.php/foo, which slips past exact-match blocks) and
    marks POST lines as attack probes: a POST to the installer on a
    finished site is never normal traffic. Returns (hits, notes).
    A hit is a probe worth investigating, not proof of a breach —
    and no hits is not a clean bill, because logs rotate and
    attackers clean up. The published exploitation began 19 Nov
    2026 19:00 UTC: check the timestamps on any hits against that
    date, this tool does not parse log timestamps.
    """
    hits = []
    notes = []
    target = Path(path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.log"))
        if not files:
            return hits, ["no .log files under %s" % path]
    else:
        return hits, ["access log path %s does not exist" % path]
    for logfile in files:
        try:
            size = logfile.stat().st_size
        except OSError:
            continue
        with logfile.open(errors="replace") as handle:
            if size > MAX_LOG_BYTES:
                handle.seek(size - MAX_LOG_BYTES)
                handle.readline()  # drop the partial first line
            for lineno, line in enumerate(handle, start=1):
                lowered = line.lower()
                if "install.php" not in lowered:
                    continue
                is_post = '"post ' in lowered or " post " in lowered
                hits.append((str(logfile), lineno, line.rstrip("\n"),
                             is_post))
                if len(hits) >= 50:
                    notes.append("hit cap reached (50), refine the search")
                    return hits, notes
    return hits, notes


def scan_ioc_dir(path):
    """Hunt a Drupal tree for uploaded PHP in the files directories.

    Walks the tree (a web root, a sites/ tree, wherever the site
    lives) for .php files under any sites/*/files directory. The
    files directory is for uploads, never for executable code — a
    .php file there is a post-exploit sign: that is where an
    attacker who just took over user 1 drops a shell. Returns
    (hits, notes). Legitimate PHP lives in core/, modules/ and
    themes/, not under files/.
    """
    target = Path(path)
    if not target.exists():
        return [], ["IOC path %s does not exist" % path]
    hits = []
    for found in sorted(target.rglob("*.php")):
        if not found.is_file():
            continue
        parts = [p.lower() for p in found.parts]
        if "files" in parts and "sites" in parts:
            hits.append(str(found))
            if len(hits) >= 50:
                return hits, ["hit cap reached (50), refine the search"]
    return hits, []


def grade_one(entry):
    """Grade one inventory entry.

    Entry keys: "version" (string), "url" (site base URL),
    "local_dir" (path string for a Drupal web/project root).
    Optional: "access_log" path, "ioc_dir" path. Returns a result
    dict.
    """
    result = {"host": entry.get("host", entry.get("url",
                                                 entry.get("version", "?")))}
    version = None
    notes = []
    if "version" in entry:
        version = parse_version(entry["version"])
        if version is None:
            notes.append("version %r is not parseable" % entry["version"])
        verdict, detail = grade(version)
        result["verdict"] = verdict
        result["detail"] = detail
    elif "url" in entry:
        verdict, detail, url_notes = probe_url(entry["url"])
        result["verdict"] = verdict
        result["detail"] = detail
        notes.extend(url_notes)
    elif "local_dir" in entry:
        version, local_notes = read_local_dir(entry["local_dir"])
        notes.extend(local_notes)
        verdict, detail = grade(version)
        result["verdict"] = verdict
        result["detail"] = detail
    else:
        return dict(result, verdict="UNKNOWN",
                    detail="entry has no version, url or local_dir",
                    notes=notes)
    if version is not None:
        result["version"] = fmt_version(version)
    result["notes"] = notes
    log_path = entry.get("access_log")
    if log_path:
        hits, log_notes = scan_access_log(log_path)
        notes.extend(log_notes)
        result["access_log_hits"] = [
            {"file": f, "line": n, "text": t, "post": p}
            for f, n, t, p in hits
        ]
        posts = [h for h in hits if h[3]]
        if hits:
            result["detail"] += (
                "; %d access-log line(s) request %s (%d POST%s) — "
                "investigate, and check timestamps against the "
                "exploitation window (from 19 Nov 2026 19:00 UTC)"
                % (len(hits), INSTALLER_PATH, len(posts),
                   "s" if len(posts) != 1 else ""))
    ioc_path = entry.get("ioc_dir")
    if ioc_path:
        hits, ioc_notes = scan_ioc_dir(ioc_path)
        notes.extend(ioc_notes)
        result["ioc_hits"] = hits
        if hits:
            result["detail"] += (
                "; %d PHP file(s) under sites/*/files (%s) — the "
                "files directory never holds executable code, so "
                "treat these as post-exploit shells until proven "
                "otherwise" % (len(hits), ", ".join(hits[:3])))
    return result


def worst_verdict(results):
    """The fleet verdict is the worst of its members."""
    order = {"VULNERABLE": 0, "UNKNOWN": 1, "FIXED": 2}
    return min(results, key=lambda r: order.get(r["verdict"], 1))["verdict"]


def print_result(result, as_json=False):
    """One result, human or machine readable."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("[%s] %s" % (result["verdict"], result["host"]))
    if "version" in result:
        print("  version: %s" % result["version"])
    print("  %s" % result["detail"])
    for note in result.get("notes", []):
        print("  note: %s" % note)
    for hit in result.get("access_log_hits", []):
        print("  log hit %s:%s%s: %s" % (
            hit["file"], hit["line"],
            " [POST — attack probe]" if hit["post"] else "", hit["text"]))
    for hit in result.get("ioc_hits", []):
        print("  ioc %s (PHP under sites/*/files — SUSPICIOUS)" % hit)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Drupal core %s (%s, "
                    "CVSS %s). Grades the core version against the %s "
                    "fix. Never sends payloads, never POSTs."
                    % (CVE_MAIN, ADVISORY, CVSS, FIX_RELEASED))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", metavar="VERSION",
                       help="grade a version string, e.g. 11.4.12")
    group.add_argument("--version-file", metavar="FILE",
                       help="read the version from a file (first line)")
    group.add_argument("--url", metavar="URL",
                       help="grade a live site from public reads: "
                            "CHANGELOG.txt, X-Generator, and one GET of "
                            "%s" % INSTALLER_PATH)
    group.add_argument("--local-dir", metavar="DIR",
                       help="grade a Drupal install on this box: the web "
                            "root or project root (CHANGELOG.txt, "
                            "core/lib/Drupal.php, composer.lock)")
    group.add_argument("--inventory-json", metavar="FILE",
                       help="grade a fleet from a JSON list of entries")
    group.add_argument("--list", action="store_true",
                       help="print the fixed-version table and exit")
    parser.add_argument("--access-log", metavar="PATH",
                        help="grep an access log (file or dir of .log) for "
                             "requests to %s" % INSTALLER_PATH)
    parser.add_argument("--ioc-dir", metavar="PATH",
                        help="hunt a Drupal tree for PHP files under "
                             "sites/*/files (uploaded shells)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print("%s — %s (%s) — CVSS %s" % (PRODUCT, CVE_MAIN, ADVISORY, CVSS))
        print("affected: <10.6.22, 11.0.0–11.3.21, 11.4.0–11.4.12; "
              "11.2.x and below, 10.5.x and below, 8, 9 end of life; "
              "11.5 beta and 12.0 affected, no fix on line yet")
        print("fixed:    10.6.22, 11.3.22, 11.4.13 (released %s; CVE "
              "published %s; exploited since %s; CISA KEV due %s)"
              % (FIX_RELEASED, CVE_PUBLISHED, EXPLOITED_SINCE, KEV_DUE))
        print("needs:    the installer reachable at %s on a finished "
              "site whose install_task is not \"done\"; some exploit "
              "paths need settings.php writable by the web server"
              % INSTALLER_PATH)
        print("also:     %s (%s, Moderately critical 14/25, gadget "
              "chain — not directly exploitable), same releases, same "
              "fix" % (CVE_COMPANION, "SA-CORE-2026-018"))
        return EXIT_CLEAN

    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("cannot read inventory: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(entries, list) or not entries:
            print("inventory must be a non-empty JSON list", file=sys.stderr)
            return EXIT_USAGE
        results = [grade_one(entry) for entry in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print_result(result)
        verdict = worst_verdict(results)
        return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
            verdict, EXIT_CLEAN)

    entry = {}
    if args.version is not None:
        entry["version"] = args.version
    elif args.version_file is not None:
        try:
            entry["version"] = Path(args.version_file).read_text().splitlines()[0]
        except (OSError, IndexError) as exc:
            print("cannot read version file: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
    elif args.url is not None:
        entry["url"] = args.url
    elif args.local_dir is not None:
        entry["local_dir"] = args.local_dir
    entry["host"] = entry.get("url") or entry.get("version") or \
        entry.get("local_dir") or "?"
    if args.access_log:
        entry["access_log"] = args.access_log
    if args.ioc_dir:
        entry["ioc_dir"] = args.ioc_dir

    result = grade_one(entry)
    print_result(result, as_json=args.json)
    return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
        result["verdict"], EXIT_CLEAN)


if __name__ == "__main__":
    sys.exit(main())
