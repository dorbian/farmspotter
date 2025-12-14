#!/usr/bin/env python3
import os
import re
import threading
import time
from typing import List, Dict, Any
from urllib.parse import urljoin

import dns.resolver
import requests
from flask import Flask, jsonify, render_template

BOOTSTRAP_DNS_NAME = os.getenv("BOOTSTRAP_DNS_NAME", "hay.honse.farm")
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "300"))  # seconds
BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.getenv("BIND_PORT", "8080"))

# Optional: force a specific resolver (comma-separated IPs), e.g. "1.1.1.1,8.8.8.8"
DNS_SERVERS = os.getenv("DNS_SERVERS", "").strip()

# Optional: override bootstrap endpoint(s) for debugging (comma-separated URLs)
BOOTSTRAP_URLS_OVERRIDE = os.getenv("BOOTSTRAP_URLS", "").strip()

app = Flask(__name__, template_folder="templates")

_state: Dict[str, Any] = {
    "servers": [],
    "bootstraps": [],
    "last_error": None,
    "last_refresh": None,
    "dns_name": BOOTSTRAP_DNS_NAME,
    "total_online": 0,
}

URL_RE = re.compile(r"https://[^\s\"']+")

ENDPOINT_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "key": "federation_summary",
        "category": "Federation",
        "name": "Known servers (summary)",
        "method": "GET",
        "path": "/api/federation/servers/summary",
        "description": "Summarised list of all servers this host knows about.",
        "probe": True,
    },
    {
        "key": "federation_servers",
        "category": "Federation",
        "name": "Known servers (full payload)",
        "method": "GET",
        "path": "/api/federation/servers",
        "description": "Full server objects including federation metadata.",
        "probe": True,
        "notes": "May return 403 if remote server requires signatures.",
    },
    {
        "key": "federation_self",
        "category": "Federation",
        "name": "Self server info",
        "method": "GET",
        "path": "/api/federation/.well-known/server",
        "description": "Identity card for this server (id, version, type).",
        "probe": True,
    },
    {
        "key": "federation_user_validation",
        "category": "Federation",
        "name": "Request user validation",
        "method": "POST",
        "path": "/api/federation/request-user-validation",
        "description": "Server-to-server request that kicks off Lodestone validation.",
        "requires_auth": True,
    },
    {
        "key": "federation_validation_response",
        "category": "Federation",
        "name": "Submit validation response",
        "method": "POST",
        "path": "/api/federation/submit-user-validation",
        "description": "Return the outcome of a Lodestone validation request.",
        "requires_auth": True,
    },
    {
        "key": "federation_user_lookup",
        "category": "Federation",
        "name": "User summary lookup",
        "method": "GET",
        "path": "/api/federation/user?UID={uid}",
        "description": "Returns character summary data for a UID.",
        "requires_auth": True,
        "format_params": {"uid": "SAMPLEUID@Server"},
    },
    {
        "key": "federation_online_snapshot",
        "category": "Federation",
        "name": "Online user snapshot",
        "method": "POST",
        "path": "/api/federation/online-users/snapshot",
        "description": "Bulk online presence publication.",
        "requires_auth": True,
    },
    {
        "key": "federation_online_event",
        "category": "Federation",
        "name": "Online user event",
        "method": "POST",
        "path": "/api/federation/online-users/event",
        "description": "Single-user online/offline events.",
        "requires_auth": True,
    },
    {
        "key": "federation_notify_download",
        "category": "Federation",
        "name": "Notify download ready",
        "method": "POST",
        "path": "/api/federation/notify-download-ready",
        "description": "Relay that a download for a user has been staged.",
        "requires_auth": True,
    },
    {
        "key": "federation_announce",
        "category": "Federation",
        "name": "Server announce",
        "method": "POST",
        "path": "/api/federation/announce",
        "description": "Register or update this server with federation peers.",
        "requires_auth": True,
    },
    {
        "key": "federation_command",
        "category": "Federation",
        "name": "Receive command",
        "method": "POST",
        "path": "/api/federation/command",
        "description": "Process signed cross-server commands.",
        "requires_auth": True,
    },
    {
        "key": "federation_group_join",
        "category": "Federation",
        "name": "Group join notifications",
        "method": "POST",
        "path": "/api/federation/group-join-notifications",
        "description": "Notify peers about group invitations/joins.",
        "requires_auth": True,
    },
    {
        "key": "federation_group_leave",
        "category": "Federation",
        "name": "Group leave notifications",
        "method": "POST",
        "path": "/api/federation/group-leave-notifications",
        "description": "Notify peers when users leave groups.",
        "requires_auth": True,
    },
    {
        "key": "federation_group_permissions",
        "category": "Federation",
        "name": "Group permission notifications",
        "method": "POST",
        "path": "/api/federation/group-permission-notifications",
        "description": "Share group permission changes with other servers.",
        "requires_auth": True,
    },
    {
        "key": "registration_validate_access",
        "category": "Registration",
        "name": "Validate access",
        "method": "POST",
        "path": "/api/registration/validate-access",
        "description": "Check if this server allows registration (handles passwords).",
    },
    {
        "key": "registration_start",
        "category": "Registration",
        "name": "Start registration",
        "method": "POST",
        "path": "/api/registration/start",
        "description": "Kick off the Lodestone verification flow.",
    },
    {
        "key": "registration_validate",
        "category": "Registration",
        "name": "Validate registration",
        "method": "POST",
        "path": "/api/registration/validate",
        "description": "Confirm the secret phrase has been set in Lodestone profile.",
    },
    {
        "key": "registration_finalize",
        "category": "Registration",
        "name": "Finalize registration",
        "method": "POST",
        "path": "/api/registration/finalize",
        "description": "Issue a UID after Lodestone validation + key hand-off.",
    },
    {
        "key": "clientauth_register",
        "category": "Client Auth",
        "name": "Register client",
        "method": "POST",
        "path": "/api/ClientAuth/register",
        "description": "Upload the client's Ed25519 public key.",
    },
    {
        "key": "clientauth_test",
        "category": "Client Auth",
        "name": "Test authentication",
        "method": "POST",
        "path": "/api/ClientAuth/test",
        "description": "Protected endpoint verifying signature/end-user auth.",
        "requires_auth": True,
    },
    {
        "key": "management_configuration",
        "category": "Management",
        "name": "Get configuration",
        "method": "GET",
        "path": "/api/management/configuration",
        "description": "Full HonseFarm + federation configuration snapshot.",
        "requires_auth": True,
    },
    {
        "key": "management_health",
        "category": "Management",
        "name": "System health",
        "method": "GET",
        "path": "/api/management/health/system",
        "description": "Host metrics such as CPU, memory, disk, and NIC usage.",
        "requires_auth": True,
    },
    {
        "key": "management_configuration_combined",
        "category": "Management",
        "name": "Update combined configuration",
        "method": "POST",
        "path": "/api/management/configuration/combined",
        "description": "Atomically update HonseFarm and federation settings.",
        "requires_auth": True,
    },
    {
        "key": "message_send",
        "category": "Messaging",
        "name": "Send broadcast message",
        "method": "POST",
        "path": "/msgc/sendMessage",
        "description": "Internal endpoint to push notifications through SignalR.",
        "requires_auth": True,
    },
]


def _normalize_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "https://" + host
    return host.rstrip("/")


def _render_endpoint_path(endpoint: Dict[str, Any]) -> str:
    template = endpoint.get("path", "")
    fmt = endpoint.get("format_params") or {}
    if not template:
        return ""
    try:
        return template.format(**fmt)
    except Exception:
        return template


def _full_endpoint_url(host: str, endpoint: Dict[str, Any]) -> str:
    base = _normalize_host(host)
    if not base:
        return ""
    rendered = _render_endpoint_path(endpoint)
    if not rendered.startswith("/"):
        rendered = "/" + rendered
    return urljoin(base + "/", rendered.lstrip("/"))


def _probe_endpoint(url: str, method: str) -> Dict[str, Any]:
    result = {"status": None, "latency_ms": None, "error": None}
    if not url:
        result["error"] = "missing hostname"
        return result

    safe_method = method if method in {"GET", "HEAD", "OPTIONS"} else "GET"
    start = time.time()
    try:
        resp = requests.request(safe_method, url, timeout=5)
        result["status"] = resp.status_code
        result["latency_ms"] = int((time.time() - start) * 1000)
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def _gather_endpoint_stats(server: Dict[str, Any]) -> List[Dict[str, Any]]:
    host = server.get("hostname") or ""
    stats: List[Dict[str, Any]] = []
    for endpoint in ENDPOINT_DEFINITIONS:
        rendered_path = _render_endpoint_path(endpoint)
        full_url = _full_endpoint_url(host, endpoint)
        stat = {
            "key": endpoint["key"],
            "category": endpoint["category"],
            "name": endpoint["name"],
            "method": endpoint["method"],
            "path": rendered_path,
            "description": endpoint["description"],
            "url": full_url,
            "requires_auth": endpoint.get("requires_auth", False),
            "notes": endpoint.get("notes"),
            "status": None,
            "latency_ms": None,
            "error": None,
        }
        if endpoint.get("format_params"):
            stat["sample_params"] = endpoint["format_params"]
        if endpoint.get("probe"):
            probe = _probe_endpoint(full_url, endpoint["method"])
            stat.update(probe)
        stats.append(stat)
    return stats


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    if DNS_SERVERS:
        r.nameservers = [x.strip() for x in DNS_SERVERS.split(",") if x.strip()]
    return r


def extract_urls(text: str) -> List[str]:
    """Extract https:// URLs from a TXT record string (robust against quotes/spacing)."""
    return URL_RE.findall(text or "")


def resolve_bootstrap_urls(domain: str) -> List[str]:
    """
    Resolve TXT records and extract bootstrap base hosts/urls.
    If TXT does not contain https://, we assume it is an HTTPS hostname.
    """
    if BOOTSTRAP_URLS_OVERRIDE:
        urls = []
        for raw in [x.strip() for x in BOOTSTRAP_URLS_OVERRIDE.split(",") if x.strip()]:
            base = raw.strip()
            if not base.startswith("http://") and not base.startswith("https://"):
                base = "https://" + base
            if not base.endswith("/api/federation/servers/summary"):
                base = base.rstrip("/") + "/api/federation/servers/summary"
            urls.append(base)
        return urls

    urls: List[str] = []
    try:
        ans = _resolver().resolve(domain, "TXT")
        for rdata in ans:
            pieces = []
            for b in getattr(rdata, "strings", []):
                try:
                    pieces.append(b.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            txt_full = "".join(pieces).strip()

            # 1) Prefer explicit https:// URLs if present
            found = extract_urls(txt_full)

            # 2) If none found, assume TXT contains a hostname-ish token
            if not found:
                # Grab first plausible hostname token (letters/digits/dots/hyphens)
                m = re.search(r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", txt_full)
                if m:
                    found = [m.group(1)]

            for raw in found:
                base = raw.strip()
                if not base.startswith("http://") and not base.startswith("https://"):
                    base = "https://" + base
                if not base.endswith("/api/federation/servers/summary"):
                    base = base.rstrip("/") + "/api/federation/servers/summary"
                if base not in urls:
                    urls.append(base)

    except Exception as e:
        _state["last_error"] = f"DNS TXT lookup failed for {domain}: {e}"
        return []

    if not urls:
        _state["last_error"] = f"No bootstrap host/url found in TXT for {domain}"
    return urls

def fetch_server_summaries(summary_url: str) -> List[Dict[str, Any]]:
    try:
        resp = requests.get(summary_url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        _state["last_error"] = f"Unexpected JSON shape from {summary_url} (expected list)"
        return []
    except Exception as e:
        _state["last_error"] = f"Error fetching {summary_url}: {e}"
        return []


def fetch_server_details(servers_url: str) -> List[Dict[str, Any]]:
    if not servers_url:
        return []
    try:
        resp = requests.get(servers_url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        _state["last_error"] = f"Unexpected JSON shape from {servers_url} (expected list)"
        return []
    except Exception as e:
        _state["last_error"] = f"Error fetching {servers_url}: {e}"
        return []


def servers_url_from_summary(summary_url: str) -> str:
    if not summary_url:
        return ""
    url = summary_url.rstrip("/")
    suffix = "/servers/summary"
    if url.endswith(suffix):
        return url[: -len("/summary")]
    if url.endswith("/servers"):
        return url
    return url + "/servers"


def refresh_once() -> None:
    bootstraps = resolve_bootstrap_urls(BOOTSTRAP_DNS_NAME)
    servers: List[Dict[str, Any]] = []
    details_by_server: Dict[str, Dict[str, Any]] = {}

    for b in bootstraps:
        for s in fetch_server_summaries(b):
            x = dict(s)
            x["_bootstrap"] = b
            servers.append(x)
        detail_url = servers_url_from_summary(b)
        for detail in fetch_server_details(detail_url):
            sid = detail.get("serverId")
            if not sid:
                continue
            if sid not in details_by_server:
                details_by_server[sid] = detail

    # Deduplicate by (serverId, hostname)
    seen = set()
    deduped = []
    for s in servers:
        key = (s.get("serverId"), s.get("hostname"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    deduped.sort(key=lambda s: (s.get("serverId") or "", s.get("name") or ""))

    for s in deduped:
        detail = details_by_server.get(s.get("serverId") or "")
        if detail:
            s["usersOnlineCount"] = detail.get("usersOnlineCount")
            s["status"] = detail.get("status")
            s["version"] = detail.get("version") or s.get("version")
            s["lastSeen"] = detail.get("lastSeen")
            s["cdnUrl"] = detail.get("cdnUrl")
        else:
            s["usersOnlineCount"] = s.get("usersOnlineCount")
        if s.get("usersOnlineCount") is None:
            s["usersOnlineCount"] = 0
        s["_endpoint_stats"] = _gather_endpoint_stats(s)

    _state["servers"] = deduped
    _state["bootstraps"] = bootstraps
    _state["last_refresh"] = int(time.time())
    _state["total_online"] = sum(
        int(s.get("usersOnlineCount") or 0) for s in deduped
    )


def refresher_loop() -> None:
    while True:
        try:
            refresh_once()
        except Exception as e:
            _state["last_error"] = f"Unexpected refresh error: {e}"
        time.sleep(REFRESH_INTERVAL)


@app.get("/api/servers")
def api_servers():
    return jsonify(_state)


@app.get("/")
def index():
    return render_template("index.html", **_state)


def main():
    refresh_once()
    print(f"[viewer] TXT lookup domain: {BOOTSTRAP_DNS_NAME}")
    print(f"[viewer] Bootstraps discovered: {_state['bootstraps']}")
    print(f"[viewer] Servers discovered: {len(_state['servers'])}")

    t = threading.Thread(target=refresher_loop, daemon=True)
    t.start()
    app.run(host=BIND_HOST, port=BIND_PORT)


if __name__ == "__main__":
    main()
