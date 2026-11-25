"""Tests for drupal_installer_scanner.py.

Everything runs against local fixtures: a synthetic Drupal tree
(CHANGELOG.txt, core/lib/Drupal.php, composer.lock), a mock Drupal
site on localhost, synthetic access logs and a synthetic sites/
tree. No real Drupal site is touched, and no payload is ever sent
— the remote probe is plain GETs of CHANGELOG.txt, the homepage
and /core/install.php, the same requests a browser or a health
check would make. No POST is made anywhere.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import drupal_installer_scanner as scanner

# ---------------------------------------------------------------- version

GRADE_CASES = [
    # (version string, expected verdict)
    ("10.6.21", "VULNERABLE"),  # one patch behind the 10.6 fix
    ("10.6.22", "FIXED"),       # first fixed 10.6 release
    ("10.6.23", "FIXED"),
    ("10.5.0", "VULNERABLE"),   # end of life, no fix
    ("10.0.0", "VULNERABLE"),
    ("11.2.0", "VULNERABLE"),   # end of life, no fix
    ("11.3.21", "VULNERABLE"),  # one patch behind the 11.3 fix
    ("11.3.22", "FIXED"),       # first fixed 11.3 release
    ("11.3.23", "FIXED"),
    ("11.4.12", "VULNERABLE"),  # the lab-proven vulnerable release
    ("11.4.13", "FIXED"),       # first fixed 11.4 release
    ("11.4.14", "FIXED"),
    ("11.5.0", "VULNERABLE"),   # PSA: affected, no fix on line yet
    ("11.5.0-beta1", "VULNERABLE"),
    ("12.0.0", "VULNERABLE"),   # PSA: affected, no fix on line yet
    ("9.5.0", "VULNERABLE"),    # end of life
    ("8.9.0", "VULNERABLE"),    # end of life
    ("7.0.0", "VULNERABLE"),    # end of life
    ("13.0.0", "UNKNOWN"),      # no advisory coverage
    ("banana", "UNKNOWN"),
    ("", "UNKNOWN"),
]


@pytest.mark.parametrize("raw,expected", GRADE_CASES)
def test_grade_versions(raw, expected):
    verdict, _detail = scanner.grade(scanner.parse_version(raw))
    assert verdict == expected, raw


def test_grade_none_is_unknown():
    assert scanner.grade(None)[0] == "UNKNOWN"


def test_parse_version_tolerates_suffixes():
    assert scanner.parse_version("11.4.13-dev") == (11, 4, 13)
    assert scanner.parse_version("11.5.0-beta1") == (11, 5, 0)
    assert scanner.parse_version("v11.4.12") == (11, 4, 12)
    assert scanner.parse_version("11.4") == (11, 4, 0)


def test_11_4_12_detail_names_fix_and_kev():
    _verdict, detail = scanner.grade(scanner.parse_version("11.4.12"))
    assert "11.4.13" in detail
    assert "2026-11-27" in detail  # CISA KEV due date


def test_eol_detail_names_no_fix():
    _verdict, detail = scanner.grade(scanner.parse_version("11.2.0"))
    assert "end-of-life" in detail


def test_11_5_detail_names_no_fix_on_line():
    _verdict, detail = scanner.grade(scanner.parse_version("11.5.0"))
    assert "no fixed release" in detail


def test_changelog_parsing():
    text = "Drupal 11.4.12, 2026-11-04\n----------------------\n"
    assert scanner.version_from_changelog(text) == (11, 4, 12)
    assert scanner.version_from_changelog("nothing here") is None


def test_drupal_php_parsing():
    text = "<?php\nclass Drupal {\n  const VERSION = '11.3.22';\n}\n"
    assert scanner.version_from_drupal_php(text) == (11, 3, 22)


def test_installer_classification():
    state, _ = scanner.classify_installer_response(
        200, "<html>Drupal already installed</html>")
    assert state == "REFUSES"
    state, _ = scanner.classify_installer_response(
        200, "<html>Choose language — Select an installation profile</html>")
    assert state == "RESUMABLE"
    state, _ = scanner.classify_installer_response(
        200, "<form>Configure site</form>")
    assert state == "RESUMABLE"
    assert scanner.classify_installer_response(403, "")[0] == "BLOCKED"
    assert scanner.classify_installer_response(404, "")[0] == "ABSENT"
    assert scanner.classify_installer_response(302, "")[0] == "REDIRECT"
    assert scanner.classify_installer_response(200, "<html>hello</html>")[0] \
        == "UNKNOWN"


# ------------------------------------------------------- mock Drupal site

def make_handler(routes):
    """routes: {path: (status, headers dict, body)}"""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = routes.get(
                self.path, (404, {}, "not found"))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    return Handler


def serve(routes):
    server = HTTPServer(("127.0.0.1", 0), make_handler(routes))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def test_probe_vulnerable_version_refusing_installer():
    routes = {
        "/CHANGELOG.txt": (200, {},
                           "Drupal 11.4.12, 2026-11-04\n"),
        "/": (200, {"X-Generator": "Drupal 11 (https://www.drupal.org)"},
              "<html>Drupal</html>"),
        "/core/install.php": (200, {},
                              "<html>Drupal already installed</html>"),
    }
    server, base = serve(routes)
    try:
        verdict, detail, notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"
    assert "11.4.13" in detail
    assert any("already installed" in n for n in notes)


def test_probe_resumable_installer_is_exploitable_condition():
    routes = {
        "/CHANGELOG.txt": (200, {},
                           "Drupal 11.4.12, 2026-11-04\n"),
        "/": (200, {}, "<html>Drupal</html>"),
        "/core/install.php": (200, {},
                              "<html>Choose language</html>"),
    }
    server, base = serve(routes)
    try:
        verdict, detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"
    assert "RESUMABLE" in detail


def test_probe_fixed_version():
    routes = {
        "/CHANGELOG.txt": (200, {},
                           "Drupal 11.4.13, 2026-11-18\n"),
        "/": (200, {}, "<html>Drupal</html>"),
        "/core/install.php": (200, {},
                              "<html>Drupal already installed</html>"),
    }
    server, base = serve(routes)
    try:
        verdict, detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "FIXED"


def test_probe_resumable_but_version_unknown():
    routes = {
        "/CHANGELOG.txt": (404, {}, "not found"),
        "/core/CHANGELOG.txt": (404, {}, "not found"),
        "/": (200, {}, "<html>hello</html>"),
        "/core/install.php": (200, {},
                              "<html>Select an installation profile</html>"),
    }
    server, base = serve(routes)
    try:
        verdict, detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"
    assert "RESUMABLE" in detail


def test_probe_blocked_installer_no_version_is_unknown():
    routes = {
        "/CHANGELOG.txt": (404, {}, "not found"),
        "/core/CHANGELOG.txt": (404, {}, "not found"),
        "/": (200, {}, "<html>hello</html>"),
        "/core/install.php": (403, {}, "forbidden"),
    }
    server, base = serve(routes)
    try:
        verdict, _detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "UNKNOWN"


def test_probe_x_generator_major_only_eol():
    routes = {
        "/CHANGELOG.txt": (404, {}, "not found"),
        "/core/CHANGELOG.txt": (404, {}, "not found"),
        "/": (200, {"X-Generator": "Drupal 9 (https://www.drupal.org)"},
              "<html>Drupal</html>"),
        "/core/install.php": (200, {},
                              "<html>Drupal already installed</html>"),
    }
    server, base = serve(routes)
    try:
        verdict, _detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"  # major 9 is end of life


# ------------------------------------------------------------ local grading

def test_local_dir_changelog(tmp_path):
    (tmp_path / "CHANGELOG.txt").write_text(
        "Drupal 10.6.21, 2026-11-04\n")
    version, notes = scanner.read_local_dir(str(tmp_path))
    assert version == (10, 6, 21)
    assert scanner.grade(version)[0] == "VULNERABLE"


def test_local_dir_drupal_php(tmp_path):
    core_lib = tmp_path / "core" / "lib"
    core_lib.mkdir(parents=True)
    (core_lib / "Drupal.php").write_text(
        "<?php\nclass Drupal {\n  const VERSION = '11.3.22';\n}\n")
    version, _notes = scanner.read_local_dir(str(tmp_path))
    assert version == (11, 3, 22)
    assert scanner.grade(version)[0] == "FIXED"


def test_local_dir_composer_lock(tmp_path):
    lock = {"packages": [{"name": "drupal/core", "version": "11.4.12"}],
            "packages-dev": []}
    (tmp_path / "composer.lock").write_text(json.dumps(lock))
    version, notes = scanner.read_local_dir(str(tmp_path))
    assert version == (11, 4, 12)
    assert "composer.lock" in notes[0]


def test_local_dir_missing(tmp_path):
    version, notes = scanner.read_local_dir(str(tmp_path))
    assert version is None
    assert "no Drupal version found" in notes[0]


# ------------------------------------------------------------ logs and IOCs

def test_access_log_flags_installer_requests(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '10.0.0.1 - - [20/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '10.0.0.2 - - [20/Nov/2026:10:01:00 +0000] "GET /core/install.php HTTP/1.1" 200 5678\n'
        '10.0.0.3 - - [20/Nov/2026:10:02:00 +0000] "POST /core/install.php HTTP/1.1" 200 9012\n'
        '10.0.0.4 - - [20/Nov/2026:10:03:00 +0000] "GET /core/install.php/foo HTTP/1.1" 200 3456\n')
    hits, _notes = scanner.scan_access_log(str(log))
    assert len(hits) == 3
    assert sum(1 for h in hits if h[3]) == 1  # exactly one POST


def test_ioc_dir_flags_php_under_files(tmp_path):
    files_dir = tmp_path / "sites" / "default" / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "shell.php").write_text("<?php evil();")
    (files_dir / "photo.jpg").write_text("not php")
    modules = tmp_path / "modules" / "custom"
    modules.mkdir(parents=True)
    (modules / "mymodule.module").write_text("<?php // legit")
    (tmp_path / "core" / "lib" / "Drupal.php").parent.mkdir(
        parents=True, exist_ok=True)
    (tmp_path / "core" / "lib" / "Drupal.php").write_text("<?php class Drupal {}")
    hits, _notes = scanner.scan_ioc_dir(str(tmp_path))
    assert hits == [str(files_dir / "shell.php")]


# ------------------------------------------------------------- entry points

def test_list_flag(capsys):
    assert scanner.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "10.6.22" in out and "11.3.22" in out and "11.4.13" in out


def test_version_flag_exit_codes(capsys):
    assert scanner.main(["--version", "11.4.12"]) == 1
    assert scanner.main(["--version", "11.4.13"]) == 0
    assert scanner.main(["--version", "banana"]) == 2
    with pytest.raises(SystemExit):
        scanner.main(["--version"])  # argparse error, missing value


def test_inventory_json(tmp_path, capsys):
    entries = [{"host": "site-a", "version": "11.4.12"},
               {"host": "site-b", "version": "11.4.13"}]
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps(entries))
    assert scanner.main(["--inventory-json", str(inv)]) == 1
    out = capsys.readouterr().out
    assert "[VULNERABLE] site-a" in out
    assert "[FIXED] site-b" in out
