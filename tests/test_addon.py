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

    def test_load_config_applies_aws_defaults(self) -> None:
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

        self.assertFalse(config["aws"]["enabled"])
        self.assertEqual(
            config["aws"]["profileSelector"]["type"], "proxyBasicAuth"
        )
        self.assertEqual(config["aws"]["profileSelector"]["username"], "aws")
        self.assertEqual(
            config["aws"]["profilePassthrough"]["hostPatterns"],
            [
                "*.amazonaws.com",
                "*.amazonaws.com.cn",
                "*.api.aws",
                "*.signin.aws.amazon.com",
            ],
        )
        self.assertEqual(
            config["aws"]["profilePassthrough"]["onMissingProfile"],
            "inspect",
        )

    def test_extract_aws_profile_from_proxy_auth(self) -> None:
        config = self._load_config(
            {
                "aws": {
                    "enabled": True,
                    "profileSelector": {"username": "aws"},
                    "profilePassthrough": {"profiles": ["prod-admin"]},
                }
            }
        )
        token = base64.b64encode(b"aws:prod-admin").decode("ascii")

        profile = addon.extract_aws_profile_from_proxy_auth(
            {"proxy-authorization": f"Basic {token}"},
            config,
        )

        self.assertEqual(profile, "prod-admin")

    def test_extract_aws_profile_from_proxy_auth_ignores_other_username(self) -> None:
        config = self._load_config(
            {
                "aws": {
                    "enabled": True,
                    "profileSelector": {"username": "aws"},
                    "profilePassthrough": {"profiles": ["prod-admin"]},
                }
            }
        )
        token = base64.b64encode(b"user:prod-admin").decode("ascii")

        profile = addon.extract_aws_profile_from_proxy_auth(
            {"proxy-authorization": f"Basic {token}"},
            config,
        )

        self.assertIsNone(profile)

    def test_evaluate_connect_passthroughs_allowed_aws_profile(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": [],
                    "allowRules": [],
                },
                "aws": {
                    "enabled": True,
                    "profilePassthrough": {"profiles": ["prod-admin"]},
                },
            }
        )

        decision = addon.evaluate_connect(
            "eks.ap-northeast-1.amazonaws.com",
            443,
            config,
            aws_profile="prod-admin",
        )

        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["action"], "passthrough")
        self.assertEqual(decision["reason"], "aws profile passthrough: prod-admin")

    def test_evaluate_connect_blocks_missing_profile_when_configured(self) -> None:
        config = self._load_config(
            {
                "tls": {"passthroughHosts": []},
                "requestFiltering": {
                    "inspectFallbackAllowedMethods": ["GET"],
                    "allowRules": [],
                },
                "aws": {
                    "enabled": True,
                    "profilePassthrough": {
                        "profiles": ["prod-admin"],
                        "onMissingProfile": "block",
                    },
                },
            }
        )

        decision = addon.evaluate_connect(
            "sts.ap-northeast-1.amazonaws.com",
            443,
            config,
        )

        self.assertFalse(decision["allowed"])
        self.assertIn("without profile selector", decision["reason"])

    def test_evaluate_request_falls_through_for_non_passthrough_profile(self) -> None:
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
                "aws": {
                    "enabled": True,
                    "profilePassthrough": {"profiles": ["prod-admin"]},
                },
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
            aws_profile="dev",
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


if __name__ == "__main__":
    unittest.main()
