"""Lightweight, Wappalyzer-style technology fingerprinting from an HTTP response.

Given the headers, cookies and a snippet of the HTML body our own audit already
fetched (see ``audit.probe_endpoint``), recognise common web technologies —
frameworks, CMS, servers, JS libraries, CDNs — that a bare ``Server`` header does
not reveal. This widens the "components" list toward what a managed EASM report
shows, from data the host already sent us. Entirely passive: no extra request, no
exploit, no third-party service.

Each signature is a (name, optional version regex, matcher) tuple. Matchers look at
the lowercased header values, the Set-Cookie names, or the body. Results are
de-duplicated by (technology, version).
"""

from __future__ import annotations

import re

# (display name, where, pattern, version_pattern|None)
#   where: "header:<name>" matches that response header's value,
#          "cookie" matches a Set-Cookie name, "body" matches the HTML body.
_SIGNATURES: list[tuple[str, str, re.Pattern[str], re.Pattern[str] | None]] = [
    # --- CMS ---
    ("WordPress", "body", re.compile(r"/wp-(?:content|includes)/", re.I),
     re.compile(r"WordPress\s+([\d.]+)", re.I)),
    ("WordPress", "header:x-powered-by", re.compile(r"\bw3\s*total\s*cache\b", re.I), None),
    ("Drupal", "body", re.compile(r"Drupal\.settings|/sites/(?:default|all)/", re.I), None),
    ("Drupal", "header:x-generator", re.compile(r"\bDrupal\b", re.I),
     re.compile(r"Drupal\s+([\d.]+)", re.I)),
    ("Joomla", "body", re.compile(r"/media/jui/|com_content|Joomla!", re.I), None),
    ("TYPO3", "body", re.compile(r"typo3temp/|TYPO3 CMS", re.I), None),
    ("Ghost", "header:x-powered-by", re.compile(r"\bGhost\b", re.I), None),
    # --- Frameworks / languages ---
    ("Laravel", "cookie", re.compile(r"laravel_session|XSRF-TOKEN", re.I), None),
    ("CodeIgniter", "cookie", re.compile(r"\bci_session\b", re.I), None),
    ("Django", "cookie", re.compile(r"\bcsrftoken\b|\bdjango", re.I), None),
    ("Ruby on Rails", "cookie", re.compile(r"_rails|_session_id", re.I), None),
    ("ASP.NET", "cookie", re.compile(r"ASP\.NET_SessionId|\.AspNetCore", re.I), None),
    ("ASP.NET", "header:x-aspnet-version", re.compile(r".+"),
     re.compile(r"([\d.]+)")),
    ("PHP", "cookie", re.compile(r"\bPHPSESSID\b", re.I), None),
    ("Java", "cookie", re.compile(r"\bJSESSIONID\b", re.I), None),
    ("Express", "header:x-powered-by", re.compile(r"\bExpress\b", re.I), None),
    ("Next.js", "header:x-powered-by", re.compile(r"\bNext\.js\b", re.I), None),
    ("Next.js", "body", re.compile(r"/_next/static/", re.I), None),
    # --- JS libraries (versioned where the URL carries it) ---
    ("jQuery", "body", re.compile(r"jquery[.-]", re.I),
     re.compile(r"jquery[.-]v?([\d.]+)(?:\.min)?\.js", re.I)),
    ("Bootstrap", "body", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I),
     re.compile(r"bootstrap[.-]v?([\d.]+)", re.I)),
    ("React", "body", re.compile(r"react(?:\.min)?\.js|data-reactroot|__REACT", re.I), None),
    ("Vue.js", "body", re.compile(r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}", re.I), None),
    ("AngularJS", "body", re.compile(r"ng-app|ng-controller|angular(?:\.min)?\.js", re.I), None),
    # --- CDN / infra (from headers) ---
    ("Cloudflare", "header:server", re.compile(r"\bcloudflare\b", re.I), None),
    ("Cloudflare", "header:cf-ray", re.compile(r".+"), None),
    ("Amazon CloudFront", "header:x-amz-cf-id", re.compile(r".+"), None),
    ("Amazon CloudFront", "header:via", re.compile(r"cloudfront", re.I), None),
    ("Akamai", "header:x-akamai-transformed", re.compile(r".+"), None),
    ("Varnish", "header:via", re.compile(r"varnish", re.I), None),
    ("Fastly", "header:x-served-by", re.compile(r"\bcache-\w+", re.I), None),
    # --- Analytics ---
    ("Google Analytics", "body", re.compile(r"google-analytics\.com/|gtag\(|googletagmanager", re.I), None),
    ("Matomo", "body", re.compile(r"matomo\.js|piwik\.js", re.I), None),
]

_COOKIE_NAME = re.compile(r"(?:^|[;,]\s*)([^=;,\s]+)=", re.M)


def _cookie_names(set_cookie: str) -> str:
    """Space-joined cookie names from one or more Set-Cookie header values."""
    return " ".join(_COOKIE_NAME.findall(set_cookie or ""))


def fingerprint(headers: dict, body: str, set_cookie: str = "") -> list[dict]:
    """Return [{technology, version?}] recognised from this response. De-duplicated."""
    headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    cookie_names = _cookie_names(set_cookie)
    body = body or ""

    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str | None) -> None:
        key = (name, version or "")
        if key not in seen:
            seen.add(key)
            entry = {"technology": f"{name} {version}" if version else name, "name": name}
            if version:
                entry["version"] = version
            found.append(entry)

    for name, where, pattern, ver_pattern in _SIGNATURES:
        if where.startswith("header:"):
            haystack = headers.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            haystack = cookie_names
        else:  # body
            haystack = body
        if not haystack or not pattern.search(haystack):
            continue
        version = None
        if ver_pattern:
            # Version regexes target the body (library URLs, generator meta) or a header.
            source = body if where == "body" else haystack
            m = ver_pattern.search(source)
            if m:
                version = m.group(1)
        add(name, version)
    return found
