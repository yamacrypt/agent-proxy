import atexit
import base64
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


class AddonTests(unittest.TestCase):
    def _load_config(self, payload: dict) -> dict:
        path = _write_temp_config(payload)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return addon.load_config(path)

    def _load_repo_config(self) -> dict:
        config_path = (
            Path(__file__).resolve().parents[1] / "config" / "example.json"
        )
        return addon.load_config(str(config_path))

    def test_load_config_applies_conditional_passthrough_defaults(self) -> None:
        config = self._load_config(
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

        self.assertEqual(config["conditionalPassthrough"], [])

    def test_load_config_normalizes_conditional_passthrough_rule(self) -> None:
        config = self._load_config(
            {
                "conditionalPassthrough": [
                    {
                        "name": "aws-profile",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "username": "aws",
                            "allowedPasswords": ["prod-*"],
                        },
                    }
                ]
            }
        )

        rule = config["conditionalPassthrough"][0]
        self.assertEqual(rule["name"], "aws-profile")
        self.assertEqual(rule["hostPatterns"], ["*.amazonaws.com"])
        self.assertEqual(rule["selector"]["type"], "proxyBasicAuth")
        self.assertEqual(rule["selector"]["username"], "aws")
        self.assertEqual(
            rule["selector"]["allowedPasswords"],
            ["prod-*"],
        )
        self.assertEqual(rule["onMissingSelector"], "inspect")

    def test_extract_proxy_basic_auth(self) -> None:
        token = base64.b64encode(b"aws:prod-admin").decode("ascii")

        credentials = addon.extract_proxy_basic_auth(
            {"proxy-authorization": f"Basic {token}"},
        )

        self.assertEqual(
            credentials,
            {"username": "aws", "password": "prod-admin"},
        )

    def test_extract_proxy_basic_auth_ignores_malformed_headers(self) -> None:
        credentials = addon.extract_proxy_basic_auth(
            {"proxy-authorization": "Basic not-valid-base64"},
        )

        self.assertIsNone(credentials)

    def test_evaluate_connect_passthroughs_allowed_selector(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [],
                },
                "conditionalPassthrough": [
                    {
                        "name": "aws-profile",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "type": "proxyBasicAuth",
                            "username": "aws",
                            "allowedPasswords": ["prod-*"],
                        },
                    }
                ],
            }
        )

        decision = addon.evaluate_connect(
            "eks.ap-northeast-1.amazonaws.com",
            443,
            config,
            proxy_basic_auth={"username": "aws", "password": "prod-admin"},
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["action"], "passthrough")
        self.assertEqual(decision["reason"], "conditional passthrough: aws-profile")

    def test_evaluate_connect_blocks_missing_selector_when_configured(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": ["GET"],
                    "allowRules": [],
                },
                "conditionalPassthrough": [
                    {
                        "name": "aws-profile",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "type": "proxyBasicAuth",
                            "username": "aws",
                            "allowedPasswords": ["prod-admin"],
                        },
                        "onMissingSelector": "block",
                    }
                ],
            }
        )

        decision = addon.evaluate_connect(
            "sts.ap-northeast-1.amazonaws.com",
            443,
            config,
        )

        self.assertFalse(decision["allowed"])
        self.assertIn("without selector", decision["reason"])

    def test_evaluate_connect_checks_later_matching_selector_before_blocking(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [],
                },
                "conditionalPassthrough": [
                    {
                        "name": "other-selector",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "type": "proxyBasicAuth",
                            "username": "other",
                            "allowedPasswords": ["prod-admin"],
                        },
                        "onMissingSelector": "block",
                    },
                    {
                        "name": "aws-profile",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "type": "proxyBasicAuth",
                            "username": "aws",
                            "allowedPasswords": ["prod-admin"],
                        },
                    },
                ],
            }
        )

        decision = addon.evaluate_connect(
            "sts.ap-northeast-1.amazonaws.com",
            443,
            config,
            proxy_basic_auth={"username": "aws", "password": "prod-admin"},
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["reason"], "conditional passthrough: aws-profile")

    def test_evaluate_request_falls_through_for_non_passthrough_selector(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [
                        {
                            "name": "aws eks list-clusters",
                            "methods": ["GET"],
                            "protocols": ["https"],
                            "hosts": ["eks.ap-northeast-1.amazonaws.com"],
                            "pathPatterns": ["/clusters*"],
                        }
                    ],
                },
                "conditionalPassthrough": [
                    {
                        "name": "aws-profile",
                        "hostPatterns": ["*.amazonaws.com"],
                        "selector": {
                            "type": "proxyBasicAuth",
                            "username": "aws",
                            "allowedPasswords": ["prod-admin"],
                        },
                    }
                ],
            }
        )

        decision = addon.evaluate_request(
            {
                "method": "GET",
                "protocol": "https",
                "hostname": "eks.ap-northeast-1.amazonaws.com",
                "port": 443,
                "path": "/clusters",
                "url": "https://eks.ap-northeast-1.amazonaws.com/clusters",
                "userAgent": "aws-cli",
                "headers": {},
            },
            config,
            proxy_basic_auth={"username": "aws", "password": "dev"},
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(
            decision["reason"], "matched allow rule: aws eks list-clusters"
        )

    def test_evaluate_connect_passthroughs_github_related_hosts(self) -> None:
        config = self._load_config(
            {
                "tls": {
                    "passthroughHosts": [
                        "github.com",
                        "*.github.com",
                        "*.githubusercontent.com",
                    ]
                },
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": ["GET"],
                    "allowRules": [],
                },
            }
        )

        github_api = addon.evaluate_connect("api.github.com", 443, config)
        github_uploads = addon.evaluate_connect("uploads.github.com", 443, config)
        githubusercontent = addon.evaluate_connect(
            "objects.githubusercontent.com", 443, config
        )

        self.assertTrue(github_api["allowed"])
        self.assertEqual(github_api["action"], "passthrough")
        self.assertTrue(github_uploads["allowed"])
        self.assertEqual(github_uploads["action"], "passthrough")
        self.assertTrue(githubusercontent["allowed"])
        self.assertEqual(githubusercontent["action"], "passthrough")

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

    def test_repo_proxy_config_aws_profile_passthrough_is_effective(self) -> None:
        config = self._load_repo_config()

        selected_profile = addon.evaluate_connect(
            "eks.ap-northeast-1.amazonaws.com",
            443,
            config,
            proxy_basic_auth={"username": "aws", "password": "prod-admin"},
        )
        other_profile = addon.evaluate_connect(
            "eks.ap-northeast-1.amazonaws.com",
            443,
            config,
            proxy_basic_auth={"username": "aws", "password": "dev"},
        )

        self.assertTrue(selected_profile["allowed"])
        self.assertEqual(selected_profile["action"], "passthrough")
        self.assertEqual(selected_profile["matchedRuleName"], "aws-profile")
        self.assertTrue(other_profile["allowed"])
        self.assertEqual(other_profile["action"], "mitm")

    def test_repo_proxy_config_aws_non_get_request_without_selector_is_blocked(
        self,
    ) -> None:
        config = self._load_repo_config()

        decision = addon.evaluate_request(
            {
                "method": "POST",
                "protocol": "https",
                "hostname": "eks.ap-northeast-1.amazonaws.com",
                "port": 443,
                "path": "/clusters",
                "url": "https://eks.ap-northeast-1.amazonaws.com/clusters",
                "userAgent": "aws-cli",
                "headers": {},
            },
            config,
        )

        self.assertFalse(decision["allowed"])


if __name__ == "__main__":
    unittest.main()
