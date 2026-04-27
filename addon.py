"""
codex-proxy mitmproxy addon
Drop-in replacement for the Node.js codex-proxy using mitmproxy/mitmdump.
Uses the same proxy.config.json format.
"""

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Optional

from mitmproxy import ctx, http, tls

# ---------------------------------------------------------------------------
# Glob matching (same semantics as the Node.js version)
# ---------------------------------------------------------------------------

_ESCAPE_RE = re.compile(r"([|\\{}()\[\]^$+?.])")
CONNECT_DECISION_TTL_SECONDS = 30


def _escape_regexp(value: str) -> str:
    return _ESCAPE_RE.sub(r"\\\1", value)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    escaped = _escape_regexp(pattern)
    escaped = escaped.replace("**", "\x00")
    escaped = escaped.replace("*", r"[\s\S]*")
    escaped = escaped.replace("?", ".")
    escaped = escaped.replace("\x00", r"[\s\S]*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def matches_globs(value: str, patterns: Optional[list[str]]) -> bool:
    if not patterns:
        return True
    return any(glob_to_regex(p).search(value) for p in patterns)


def matches_ports(port: Optional[int], ports: Optional[list[int]]) -> bool:
    if not ports:
        return True
    return port is not None and port in ports


def matches_method(method: str, allowed: list[str]) -> bool:
    m = method.upper()
    normed = [a.upper() for a in allowed]
    return "*" in normed or m in normed


def matches_protocols(protocol: str, allowed: Optional[list[str]]) -> bool:
    if not allowed:
        return True
    p = protocol.lower()
    normed = [a.lower() for a in allowed]
    return "*" in normed or p in normed


def matches_headers(
    headers: dict[str, str], patterns: Optional[dict[str, list[str]]]
) -> bool:
    if not patterns:
        return True
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    for header_name, pats in patterns.items():
        value = normalized_headers.get(header_name.lower())
        if value is None or not matches_globs(value, pats):
            return False
    return True


def validate_keys(value: dict[str, Any], label: str, allowed: list[str]) -> None:
    unknown = [key for key in value.keys() if key not in allowed]
    if unknown:
        raise ValueError(f"{label} has unknown keys: {', '.join(unknown)}")


def get_optional_object(
    value: Any, label: str
) -> Optional[dict[str, Any]]:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def get_optional_string_array(
    record: dict[str, Any], key: str, label: str
) -> Optional[list[str]]:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{label} must be a string array")
    return value


def string_array_or_default(
    value: Optional[list[str]], default: list[str]
) -> list[str]:
    if value is None:
        return default
    return value


# ---------------------------------------------------------------------------
# Rule evaluation (same logic as rules.ts)
# ---------------------------------------------------------------------------


def matches_rule(request: dict[str, Any], rule: dict[str, Any]) -> bool:
    if not matches_method(request["method"], rule["methods"]):
        return False
    if not matches_protocols(request["protocol"], rule.get("protocols")):
        return False
    if not matches_globs(request["hostname"], rule.get("hosts")):
        return False
    if not matches_ports(request.get("port"), rule.get("ports")):
        return False
    if not matches_globs(request["path"], rule.get("pathPatterns")):
        return False
    if not matches_globs(request["url"], rule.get("urlPatterns")):
        return False
    if not matches_globs(request["userAgent"], rule.get("userAgents")):
        return False
    if not matches_headers(request["headers"], rule.get("headerPatterns")):
        return False
    return True


def find_inspect_rule_for_host(
    hostname: str, config: dict[str, Any]
) -> Optional[dict[str, Any]]:
    for rule in config["requestFiltering"]["allowRules"]:
        hosts = rule.get("hosts")
        if not hosts or matches_globs(hostname, hosts):
            return rule
    return None


def host_has_explicit_rules(hostname: str, config: dict[str, Any]) -> bool:
    return find_inspect_rule_for_host(hostname, config) is not None


def evaluate_request(
    request: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    method = request["method"].upper()
    default_methods = [
        m.upper()
        for m in config["requestFiltering"]["inspectFallbackAllowedMethods"]
    ]

    if config["tls"]["passthroughHosts"] and matches_globs(
        request["hostname"], config["tls"]["passthroughHosts"]
    ):
        return {
            "allowed": True,
            "reason": f"passthrough host: {request['hostname']}",
        }

    if host_has_explicit_rules(request["hostname"], config):
        for rule in config["requestFiltering"]["allowRules"]:
            if matches_rule(request, rule):
                return {
                    "allowed": True,
                    "reason": f"matched allow rule: {rule['name']}",
                    "matchedRuleName": rule["name"],
                }
    elif method in default_methods:
        return {"allowed": True, "reason": f"inspect fallback allow: {method}"}

    return {"allowed": False, "reason": f"blocked {method} {request['url']}"}


def evaluate_connect(
    hostname: str,
    port: int,
    config: dict[str, Any],
) -> dict[str, Any]:
    if config["tls"]["passthroughHosts"] and matches_globs(
        hostname, config["tls"]["passthroughHosts"]
    ):
        return {
            "allowed": True,
            "action": "passthrough",
            "reason": f"passthrough host: {hostname}",
        }

    matched_rule = find_inspect_rule_for_host(hostname, config)
    if matched_rule:
        return {
            "allowed": True,
            "action": "mitm",
            "reason": f"inspect host from rule: {matched_rule['name']}",
            "matchedRuleName": matched_rule["name"],
        }

    if config["requestFiltering"]["inspectFallbackAllowedMethods"]:
        return {
            "allowed": True,
            "action": "mitm",
            "reason": f"inspect fallback: {hostname}",
        }

    return {"allowed": False, "reason": f"blocked CONNECT {hostname}:{port}"}


# ---------------------------------------------------------------------------
# Config loading (same JSON format as proxy.config.json)
# ---------------------------------------------------------------------------


def load_config(config_path: str) -> dict[str, Any]:
    with open(config_path) as f:
        raw = json.load(f)

    if not isinstance(raw, dict):
        raise ValueError("config root must be an object")

    validate_keys(
        raw,
        "config",
        [
            "host",
            "port",
            "suppressTlsClientErrors",
            "tls",
            "requestFiltering",
        ],
    )

    tls = get_optional_object(raw.get("tls"), "tls") or {}
    request_filtering = (
        get_optional_object(raw.get("requestFiltering"), "requestFiltering") or {}
    )
    validate_keys(tls, "tls", ["passthroughHosts"])
    validate_keys(
        request_filtering,
        "requestFiltering",
        ["inspectFallbackAllowedMethods", "allowRules"],
    )
    allow_rules = request_filtering.get("allowRules", [])
    if not isinstance(allow_rules, list):
        raise ValueError("requestFiltering.allowRules must be an array")

    return {
        "host": raw.get("host", "127.0.0.1"),
        "port": raw.get("port", 8787),
        "suppressTlsClientErrors": raw.get("suppressTlsClientErrors", True),
        "tls": {
            "passthroughHosts": string_array_or_default(
                get_optional_string_array(
                    tls, "passthroughHosts", "tls.passthroughHosts"
                ),
                [],
            ),
        },
        "requestFiltering": {
            "inspectFallbackAllowedMethods": string_array_or_default(
                get_optional_string_array(
                    request_filtering,
                    "inspectFallbackAllowedMethods",
                    "requestFiltering.inspectFallbackAllowedMethods",
                ),
                ["GET"],
            ),
            "allowRules": allow_rules,
        },
    }


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------


class CodexProxy:
    def __init__(self) -> None:
        self.config_path = os.environ.get(
            "CODEX_PROXY_CONFIG",
            str(Path(__file__).parent / "config" / "proxy.config.json"),
        )
        self.config = load_config(self.config_path)
        self._connect_decisions: dict[tuple[str, str, int], dict[str, Any]] = {}
        self._start_watcher()

    def _cache_key(
        self, client_id: Optional[Any], hostname: str, port: int
    ) -> Optional[tuple[str, str, int]]:
        if client_id is None:
            return None
        return (str(client_id), hostname.lower(), port)

    def _prune_connect_decisions(
        self, client_id: Optional[Any] = None
    ) -> None:
        now = time.time()
        target_client = str(client_id) if client_id is not None else None
        keys_to_delete: list[tuple[str, str, int]] = []

        for key, decision in self._connect_decisions.items():
            expired = decision.get("expiresAt", 0) <= now
            same_client = target_client is not None and key[0] == target_client
            if expired or same_client:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            self._connect_decisions.pop(key, None)

    def _store_connect_decision(
        self,
        client_id: Optional[Any],
        hostname: str,
        port: int,
        decision: dict[str, Any],
    ) -> None:
        cache_key = self._cache_key(client_id, hostname, port)
        if cache_key is None:
            return

        self._prune_connect_decisions()
        cached = dict(decision)
        cached["expiresAt"] = time.time() + CONNECT_DECISION_TTL_SECONDS
        self._connect_decisions[cache_key] = cached

    def _get_connect_decision(
        self, client_id: Optional[Any], hostname: str, port: int
    ) -> Optional[dict[str, Any]]:
        cache_key = self._cache_key(client_id, hostname, port)
        if cache_key is None:
            return None

        self._prune_connect_decisions()
        decision = self._connect_decisions.get(cache_key)
        if not decision:
            return None
        return dict(decision)

    def _strip_proxy_authorization(self, headers: Any) -> None:
        for header_name in list(headers.keys()):
            if header_name.lower() == "proxy-authorization":
                del headers[header_name]

    # -- config hot-reload --------------------------------------------------

    def _start_watcher(self) -> None:
        def watch() -> None:
            last_mtime = os.stat(self.config_path).st_mtime
            while True:
                time.sleep(1)
                try:
                    mtime = os.stat(self.config_path).st_mtime
                    if mtime != last_mtime:
                        last_mtime = mtime
                        self.config = load_config(self.config_path)
                        ctx.log.info(
                            f"[config-reload] reloaded from {self.config_path}"
                        )
                except FileNotFoundError:
                    pass
                except Exception as e:
                    ctx.log.error(f"[config-reload] failed: {e}")

        threading.Thread(target=watch, daemon=True).start()

    # -- CONNECT handling ---------------------------------------------------

    def http_connect(self, flow: http.HTTPFlow) -> None:
        hostname = flow.request.host
        port = flow.request.port
        decision = evaluate_connect(
            hostname,
            port,
            self.config,
        )
        self._store_connect_decision(
            getattr(flow.client_conn, "id", None),
            hostname,
            port,
            decision,
        )
        self._strip_proxy_authorization(flow.request.headers)

        if not decision["allowed"]:
            ctx.log.warn(
                f'[blocked] CONNECT {hostname}:{port} '
                f'reason="{decision["reason"]}"'
            )
            flow.response = http.Response.make(403, b"Forbidden\n")
            return

        action = decision.get("action", "mitm")
        ctx.log.info(
            f'[{action}] CONNECT {hostname}:{port} '
            f'reason="{decision["reason"]}"'
        )

    # -- TLS passthrough decision -------------------------------------------

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        server = data.context.server.address
        if not server:
            return
        hostname, port = server[0], server[1]
        client = getattr(data.context, "client", None)
        client_id = getattr(client, "id", None)
        decision = self._get_connect_decision(client_id, hostname, port)
        if decision is None:
            decision = evaluate_connect(hostname, port, self.config)
        if decision.get("allowed") and decision.get("action") == "passthrough":
            data.ignore_connection = True

    # -- HTTP / WebSocket request filtering ---------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        scheme = flow.request.scheme
        is_ws = flow.request.headers.get("upgrade", "").lower() == "websocket"
        protocol = ("wss" if scheme == "https" else "ws") if is_ws else scheme
        self._strip_proxy_authorization(flow.request.headers)

        request_meta: dict[str, Any] = {
            "method": flow.request.method,
            "protocol": protocol,
            "hostname": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "url": flow.request.url,
            "userAgent": flow.request.headers.get("user-agent", ""),
            "headers": {
                k.lower(): v for k, v in flow.request.headers.items()
            },
        }

        decision = evaluate_request(
            request_meta,
            self.config,
        )

        if not decision["allowed"]:
            ua = request_meta["userAgent"]
            ctx.log.warn(
                f'[blocked] {request_meta["method"]} {request_meta["url"]}'
                f' userAgent="{ua}" '
                f'reason="{decision["reason"]}"'
            )
            body = json.dumps(
                {
                    "error": "REQUEST_BLOCKED",
                    "reason": decision["reason"],
                    "request": {
                        k: v for k, v in request_meta.items() if k != "headers"
                    },
                },
                indent=2,
            )
            flow.response = http.Response.make(
                403,
                body.encode(),
                {"Content-Type": "application/json; charset=utf-8"},
            )
            return

        ctx.log.info(
            f'[allowed] {request_meta["method"]} {request_meta["url"]}'
            f' reason="{decision["reason"]}"'
        )

    def client_disconnected(self, client: Any) -> None:
        self._prune_connect_decisions(getattr(client, "id", None))


addons = [CodexProxy()]
