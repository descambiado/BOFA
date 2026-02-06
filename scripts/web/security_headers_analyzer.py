#!/usr/bin/env python3
"""
Web Security Headers Analyzer - BOFA
====================================

Analiza las cabeceras HTTP de una URL y genera un resumen de seguridad
en formato JSON opcional. Comprueba cabeceras como:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Cookies (Secure, HttpOnly, SameSite)

Uso:
    python3 security_headers_analyzer.py --url https://example.com --json
"""

import argparse
import json
import sys
from http.cookies import SimpleCookie
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def _parse_cookies(set_cookie_headers):
    """Parsea cookies y comprueba atributos de seguridad basicos."""
    cookies_info = []
    if not set_cookie_headers:
        return cookies_info
    # set_cookie_headers puede ser str o lista
    if isinstance(set_cookie_headers, str):
        raw_headers = [set_cookie_headers]
    else:
        raw_headers = list(set_cookie_headers)
    for raw in raw_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            attrs = {k.lower(): (v or "") for k, v in morsel.items() if v}
            info = {
                "name": name,
                "secure": "secure" in attrs or "secure" in raw.lower(),
                "httponly": "httponly" in attrs or "httponly" in raw.lower(),
                "samesite": attrs.get("samesite", "").lower(),
            }
            cookies_info.append(info)
    return cookies_info


def _score_headers(headers, cookies_info):
    """Genera un resumen de seguridad basico a partir de cabeceras y cookies."""
    h = {k.lower(): v for k, v in headers.items()}
    issues = []

    # HSTS
    hsts = h.get("strict-transport-security")
    if not hsts:
        issues.append({"header": "Strict-Transport-Security", "severity": "HIGH", "detail": "HSTS no presente"})

    # CSP
    csp = h.get("content-security-policy")
    if not csp:
        issues.append({"header": "Content-Security-Policy", "severity": "HIGH", "detail": "CSP no presente"})

    # X-Frame-Options
    xfo = h.get("x-frame-options")
    if not xfo:
        issues.append({"header": "X-Frame-Options", "severity": "MEDIUM", "detail": "X-Frame-Options no presente"})

    # X-Content-Type-Options
    xcto = h.get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        issues.append({"header": "X-Content-Type-Options", "severity": "MEDIUM", "detail": "X-Content-Type-Options absent o distinto de nosniff"})

    # Referrer-Policy
    refpol = h.get("referrer-policy")
    if not refpol:
        issues.append({"header": "Referrer-Policy", "severity": "LOW", "detail": "Referrer-Policy no presente"})

    # Cookies
    weak_cookies = []
    for c in cookies_info:
        if not c["secure"] or not c["httponly"]:
            weak_cookies.append(c)
    if weak_cookies:
        issues.append({"header": "Set-Cookie", "severity": "HIGH", "detail": f"{len(weak_cookies)} cookies sin Secure o HttpOnly"})

    # Calcular puntuacion muy simple
    score = 100
    for issue in issues:
        if issue["severity"] == "HIGH":
            score -= 25
        elif issue["severity"] == "MEDIUM":
            score -= 10
        else:
            score -= 5
    if score < 0:
        score = 0

    summary = {
        "score": score,
        "issues": issues,
        "has_hsts": bool(hsts),
        "has_csp": bool(csp),
        "has_x_frame_options": bool(xfo),
        "has_x_content_type_options": bool(xcto and xcto.lower() == "nosniff"),
        "has_referrer_policy": bool(refpol),
        "cookies": cookies_info,
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Analizar cabeceras de seguridad HTTP de una URL")
    parser.add_argument("--url", type=str, required=True, help="URL objetivo (ej. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout en segundos (default 10)")
    parser.add_argument("--json", action="store_true", help="Salida JSON (recomendada para IA/flows)")
    args = parser.parse_args()

    try:
        req = Request(args.url, method="GET")
        req.add_header("User-Agent", "BOFA-Web-Security/1.0")
        with urlopen(req, timeout=args.timeout) as resp:
            # headers es email.message.Message; usar get_all para cookies
            raw_headers = resp.headers
            headers_dict = dict(raw_headers.items())
            cookies = raw_headers.get_all("Set-Cookie") or []
            cookies_info = _parse_cookies(cookies)
            summary = _score_headers(headers_dict, cookies_info)
            summary["url"] = args.url
            summary["status"] = getattr(resp, "status", None)
    except (HTTPError, URLError, OSError) as e:
        err = {"error": str(e), "url": args.url}
        if args.json:
            print(json.dumps(err, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"URL: {summary['url']}")
        print(f"Status: {summary['status']}")
        print(f"Score: {summary['score']}")
        if summary["issues"]:
            print("Issues:")
            for issue in summary["issues"]:
                print(f"  - [{issue['severity']}] {issue['header']}: {issue['detail']}")
        else:
            print("No se han detectado problemas de cabeceras basicas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

