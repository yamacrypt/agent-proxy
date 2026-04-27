import atexit
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


def _write_temp_config(payload: dict) -> str:
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
    )
    json.dump(payload, handle)
    handle.close()
    return handle.name


def _install_mitmproxy_stub() -> None:
    if "mitmproxy" in sys.modules:
        return

    class _Log:
        def info(self, *_args, **_kwargs) -> None:
            pass

        def warn(self, *_args, **_kwargs) -> None:
            pass

        def error(self, *_args, **_kwargs) -> None:
            pass

    class _Response:
        @staticmethod
        def make(status_code, body, headers=None):
            return {
                "status_code": status_code,
                "body": body,
                "headers": headers or {},
            }

    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.ctx = types.SimpleNamespace(log=_Log())
    mitmproxy.http = types.SimpleNamespace(Response=_Response, HTTPFlow=object)
    mitmproxy.tls = types.SimpleNamespace(ClientHelloData=object)
    sys.modules["mitmproxy"] = mitmproxy


BOOTSTRAP_CONFIG = _write_temp_config(
    {
        "host": "127.0.0.1",
        "port": 8787,
        "tls": {"passthroughHosts": []},
        "requestFiltering": {
            "inspectFallbackAllowedMethods": ["GET"],
            "allowRules": [],
        },
    }
)
atexit.register(lambda: os.path.exists(BOOTSTRAP_CONFIG) and os.unlink(BOOTSTRAP_CONFIG))
os.environ["CODEX_PROXY_CONFIG"] = BOOTSTRAP_CONFIG
_install_mitmproxy_stub()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
addon = importlib.import_module("addon")


def _request(
    method: str = "GET",
    hostname: str = "api.example.com",
    path: str = "/v1/messages",
    headers: dict[str, str] | None = None,
) -> dict:
    return {
        "method": method,
        "protocol": "https",
        "hostname": hostname,
        "port": 443,
        "path": path,
        "url": f"https://{hostname}{path}",
        "userAgent": "client",
        "headers": headers or {},
    }


class AddonTests(unittest.TestCase):
    def _load_config(self, payload: dict) -> dict:
        path = _write_temp_config(payload)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return addon.load_config(path)

    def _load_repo_config(self) -> dict:
        config_path = (
            Path(__file__).resolve().parents[1]
            / "config"
            / "proxy.config.example.json"
        )
        return addon.load_config(str(config_path))

    def test_load_config_applies_defaults(self) -> None:
        config = self._load_config({})

        self.assertEqual(config["host"], "127.0.0.1")
        self.assertEqual(config["port"], 8787)
        self.assertEqual(config["tls"]["passthroughHosts"], [])
        self.assertEqual(
            config["requestFiltering"]["inspectFallbackAllowedMethods"],
            ["GET"],
        )
        self.assertEqual(config["requestFiltering"]["allowRules"], [])

    def test_load_config_rejects_conditional_passthrough(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown keys"):
            self._load_config({"conditionalPassthrough": []})

    def test_evaluate_connect_passthroughs_static_hosts_first(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": ["api.example.com"]},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [],
                },
            }
        )

        decision = addon.evaluate_connect("api.example.com", 443, config)

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["action"], "passthrough")

    def test_evaluate_connect_mitms_host_matched_by_allow_rule(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "aws token",
                            "methods": ["*"],
                            "hosts": ["*.amazonaws.com"],
                            "headerPatterns": {
                                "authorization": ["*accessToken=1111*"],
                            },
                        }
                    ],
                },
            }
        )

        decision = addon.evaluate_connect(
            "ec2.ap-northeast-1.amazonaws.com",
            443,
            config,
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["action"], "mitm")
        self.assertEqual(decision["matchedRuleName"], "aws token")

    def test_evaluate_connect_mitms_all_hosts_for_allow_rule_without_hosts(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "token anywhere",
                            "methods": ["*"],
                            "headerPatterns": {
                                "authorization": ["*accessToken=1111*"],
                            },
                        }
                    ],
                },
            }
        )

        decision = addon.evaluate_connect("anything.example.com", 443, config)

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["action"], "mitm")
        self.assertEqual(decision["matchedRuleName"], "token anywhere")

    def test_evaluate_connect_blocks_unknown_host_without_rules_or_fallback(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [],
                },
            }
        )

        decision = addon.evaluate_connect("example.com", 443, config)

        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "blocked CONNECT example.com:443")

    def test_evaluate_request_allows_any_method_with_matching_authorization(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "token anywhere",
                            "methods": ["*"],
                            "headerPatterns": {
                                "authorization": ["*accessToken=1111*"],
                            },
                        }
                    ],
                },
            }
        )

        for method in ["GET", "POST", "PUT", "DELETE"]:
            with self.subTest(method=method):
                decision = addon.evaluate_request(
                    _request(
                        method=method,
                        headers={"Authorization": "Bearer accessToken=1111"},
                    ),
                    config,
                )

                self.assertTrue(decision["allowed"])
                self.assertEqual(decision["matchedRuleName"], "token anywhere")

    def test_evaluate_request_blocks_when_authorization_does_not_match(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "token anywhere",
                            "methods": ["*"],
                            "headerPatterns": {
                                "authorization": ["*accessToken=1111*"],
                            },
                        }
                    ],
                },
            }
        )

        decision = addon.evaluate_request(
            _request(method="POST", headers={"Authorization": "Bearer nope"}),
            config,
        )

        self.assertFalse(decision["allowed"])

    def test_evaluate_request_matches_header_patterns_case_insensitively(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "api json",
                            "methods": ["POST"],
                            "hosts": ["api.example.com"],
                            "headerPatterns": {
                                "content-type": ["application/json*"],
                            },
                        }
                    ],
                },
            }
        )

        decision = addon.evaluate_request(
            _request(
                method="POST",
                headers={"Content-Type": "Application/JSON; charset=utf-8"},
            ),
            config,
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["matchedRuleName"], "api json")

    def test_evaluate_request_does_not_use_fallback_for_explicit_host_rule(
        self,
    ) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": ["POST"],
                    "allowRules": [
                        {
                            "name": "api get",
                            "methods": ["GET"],
                            "hosts": ["api.example.com"],
                            "pathPatterns": ["/v1/messages"],
                        }
                    ],
                },
            }
        )

        decision = addon.evaluate_request(_request(method="POST"), config)

        self.assertFalse(decision["allowed"])

    def test_evaluate_request_allows_fallback_method_for_unknown_host(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": ["GET"],
                    "allowRules": [],
                },
            }
        )

        decision = addon.evaluate_request(_request(method="GET"), config)

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["reason"], "inspect fallback allow: GET")

    def test_repo_proxy_config_passthrough_hosts_are_effective(self) -> None:
        config = self._load_repo_config()

        openai = addon.evaluate_connect("api.openai.com", 443, config)
        github_assets = addon.evaluate_connect(
            "objects.githubusercontent.com", 443, config
        )

        self.assertTrue(openai["allowed"])
        self.assertEqual(openai["action"], "passthrough")
        self.assertTrue(github_assets["allowed"])
        self.assertEqual(github_assets["action"], "passthrough")

    def test_repo_proxy_config_security_token_allows_all_methods(self) -> None:
        config = self._load_repo_config()

        connect = addon.evaluate_connect("ec2.ap-northeast-1.amazonaws.com", 443, config)
        request = addon.evaluate_request(
            _request(
                method="POST",
                hostname="ec2.ap-northeast-1.amazonaws.com",
                path="/",
                headers={"X-Amz-Security-Token": "your_aws_session_token"},
            ),
            config,
        )

        self.assertTrue(connect["allowed"])
        self.assertEqual(connect["action"], "mitm")
        self.assertTrue(request["allowed"])
        self.assertEqual(request["matchedRuleName"], "authorization access token")

    def test_repo_proxy_config_blocks_non_matching_post(self) -> None:
        config = self._load_repo_config()

        decision = addon.evaluate_request(
            _request(
                method="POST",
                hostname="ec2.ap-northeast-1.amazonaws.com",
                path="/",
                headers={"Authorization": "AWS4-HMAC-SHA256"},
            ),
            config,
        )

        self.assertFalse(decision["allowed"])


if __name__ == "__main__":
    unittest.main()
