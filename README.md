# mitmproxy-proxy

`mitmproxy` に一本化したローカル proxy です。CA は `mitmproxy` 標準の `~/.mitmproxy` を使います。

新しく入る人向けの詳細は [ONBOARDING.md](/home/yanto/codex-proxy/mitmproxy-proxy/ONBOARDING.md) にまとめています。

## ポイント

- CA は `mitmproxy` が初回起動時に `~/.mitmproxy/` に生成
- `allowRules[].hosts` に入った host は自動で `inspect` される
- host ごとの証明書登録は不要
- `tls.passthroughHosts` は CA 不要
- `requestFiltering.allowRules[].hosts` は CA 必要

## 1回だけやること

まず `mitmdump` を 1 回起動して CA を生成します。

```bash
cd ~/codex-proxy/mitmproxy-proxy
./start.sh
```

そのあと Ubuntu / WSL では次を実行します。

```bash
cd ~/codex-proxy/mitmproxy-proxy
./install-ca.sh
```

中でやっていることはこれです。

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

これでこの `mitmproxy` CA がシステムで信頼されます。`mitmproxy` がその CA で発行する `localhost` や任意 host の証明書も同じ trust chain で通ります。

注意:

- `~/.mitmproxy` を消して CA が再生成されたら、再登録が必要
- 一部ツールは system CA を見ないので、その場合は個別に `SSL_CERT_FILE` や `AWS_CA_BUNDLE` が必要

AWS CLI v2 について:

- `update-ca-certificates` をしていても、AWS CLI v2 は system trust store ではなく自前の CA bundle を使うことがあります
- その場合、proxy 経由の `aws eks list-clusters` は `CERTIFICATE_VERIFY_FAILED` で落ちます
- いちばん安定するのは `~/.aws/config` の `[default]` に `ca_bundle = /etc/ssl/certs/ca-certificates.crt` を入れるやり方です

```ini
[default]
region = ap-northeast-1
ca_bundle = /etc/ssl/certs/ca-certificates.crt
```

注意:

- `ca_bundle` は `[default]` セクションに入れる
- パスは `.crt` まで含めて正確に書く
- `.cr` などにすると効かず、proxy 経由だけ unknown ca になります

## 起動

```bash
cd ~/codex-proxy/mitmproxy-proxy
./start.sh
```

バックグラウンド起動:

```bash
cd ~/codex-proxy/mitmproxy-proxy
./background.sh
```

## config の意味

設定ファイルは [config/proxy.config.json](/home/yanto/codex-proxy/mitmproxy-proxy/config/proxy.config.json) です。

- `tls.passthroughHosts`: CA なしで素通しする host
- `requestFiltering.inspectFallbackAllowedMethods`: 未知 host を inspect したときの既定許可 method
- `requestFiltering.allowRules`: inspect 済み request の allow ルール。`hosts` に書いた host は自動で inspect 対象になる

重要:

- `requestFiltering.allowRules[].hosts` に書いた host は自動で MITM されます
- `tls.passthroughHosts` にも同じ host を書いた場合は passthrough が優先です
- `requestFiltering.allowRules[].hosts` に一致する host では fallback より rule が優先です
- AWS SSO のように CA なしで通したいものは `tls.passthroughHosts` に入れます
