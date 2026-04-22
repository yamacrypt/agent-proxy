# mitmproxy-proxy Onboarding

`mitmproxy-proxy` を新しく使い始める人向けのメモです。

このドキュメントでは次を説明します。

- `~/.mitmproxy` に何ができるか
- `mitmproxy` の自己署名ルート CA がどう作られるか
- Ubuntu / WSL でその CA を 1 回だけ信頼する方法
- `proxy.config.json` の読み方

## 全体像

`mitmproxy` は HTTPS を inspect するとき、自分でルート CA を 1 つ持ちます。

- そのルート CA が `~/.mitmproxy/mitmproxy-ca-cert.pem`
- `mitmproxy` はその CA を使って、接続先 host ごとの証明書を動的に発行します
- クライアントがこの CA を信頼していれば、`mitmproxy` 経由の HTTPS MITM が通ります

大事なのは、host ごとに CA を作るわけではないことです。

- ルート CA は 1 つ
- `chatgpt.com` でも `eks.ap-northeast-1.amazonaws.com` でも `localhost` でも、`mitmproxy` が差し替える証明書はこの同じルート CA で署名されます

## `~/.mitmproxy` にあるもの

初回起動後、`~/.mitmproxy/` にだいたい次のファイルができます。

- `mitmproxy-ca-cert.pem`
  公開用のルート CA 証明書。システムに登録するのはこれ
- `mitmproxy-ca.pem`
  CA の秘密鍵を含む PEM。外に配らない
- `mitmproxy-ca-cert.cer`
  別拡張子の証明書
- `mitmproxy-ca-cert.p12`
  PKCS#12 形式の証明書
- `mitmproxy-ca.p12`
  PKCS#12 形式
- `mitmproxy-dhparam.pem`
  TLS 用パラメータ

普段いちばん使うのはこれです。

```bash
~/.mitmproxy/mitmproxy-ca-cert.pem
```

## 自己署名ルート CA はいつ作られるか

`mitmproxy` または `mitmdump` を、まだ CA がない状態で最初に起動したときに自動生成されます。

この repo では次で作れます。

```bash
cd ~/codex-proxy/mitmproxy-proxy
./start.sh
```

生成後に確認:

```bash
ls -la ~/.mitmproxy
openssl x509 -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout -subject -issuer -fingerprint -sha256
```

`subject` と `issuer` がどちらも `mitmproxy` なら、自己署名ルート CA です。

## CA を作り直したいとき

`~/.mitmproxy` を消してから `mitmproxy` を再起動すると、新しい CA が生成されます。

```bash
rm -rf ~/.mitmproxy
cd ~/codex-proxy/mitmproxy-proxy
./start.sh
```

注意:

- CA を作り直すと、前に system trust store に入れた CA はもう使えません
- 作り直したあとは、もう一度 CA を登録し直す必要があります

## Ubuntu / WSL で 1 回だけ信頼する

Ubuntu / WSL では次で system trust store に入れられます。

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

この repo では helper script もあります。

```bash
cd ~/codex-proxy/mitmproxy-proxy
./install-ca.sh
```

これが終わると、その CA で `mitmproxy` が発行する証明書は同じ trust chain で扱われます。毎回 host を登録する必要はありません。

## それでも unknown ca になるとき

system CA を見ないクライアントがあります。

代表例:

- Python の `requests` / botocore 系
- Node.js 系ツール
- 独自の trust store を持つ GUI アプリ

その場合は追加で環境変数を渡します。

Python / AWS CLI:

```bash
export SSL_CERT_FILE="/$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export REQUESTS_CA_BUNDLE="/$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export AWS_CA_BUNDLE="/$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
```

Node.js:

```bash
export NODE_EXTRA_CA_CERTS="/$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
```

## AWS CLI v2 で特に注意すること

AWS CLI v2 は、system trust store をそのまま使わず、自前の CA bundle を見ることがあります。

そのため、Ubuntu / WSL で `sudo update-ca-certificates` を実行済みでも、proxy 経由の AWS API だけが次のように失敗することがあります。

```text
SSL validation failed for https://eks.ap-northeast-1.amazonaws.com/clusters
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate
```

この症状が出たら、まず `~/.aws/config` の `[default]` に `ca_bundle` を入れてください。

```ini
[default]
region = ap-northeast-1
ca_bundle = /etc/ssl/certs/ca-certificates.crt
```

背景:

- `mitmproxy` の CA は system trust store に入っている
- でも AWS CLI v2 は別の CA bundle を参照していることがある
- その結果、直実行は通るのに proxy 経由だけ unknown ca になる

確認コマンド:

```bash
aws configure get ca_bundle
aws configure list
```

期待する値:

- `aws configure get ca_bundle` が `/etc/ssl/certs/ca-certificates.crt`
- `aws configure list` の `profile` が意図したもの

よくあるミス:

- `ca_bundle` を `[default]` ではなく別セクションに入れてしまう
- `/etc/ssl/certs/ca-certificates.crt` を typo する
  例: `.cr` と書くと効かない
- `AWS_CA_BUNDLE` 環境変数が残っていて、config よりそちらが優先される

一時的に環境変数で通すならこれでも構いません。

```bash
export AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

ただし毎回入れるのは面倒なので、通常は `~/.aws/config` の `[default]` に書くのがおすすめです。

## `proxy.config.json` の考え方

設定ファイルはここです。

[proxy.config.json](/home/yanto/codex-proxy/mitmproxy-proxy/config/proxy.config.json)

いまの schema は大きく 2 つです。

- `tls`
- `requestFiltering`

### `tls.passthroughHosts`

CA なしで素通しする host の一覧です。

```json
{
  "tls": {
    "passthroughHosts": [
      "localhost",
      "127.0.0.1",
      "oidc.ap-northeast-1.amazonaws.com"
    ]
  }
}
```

特徴:

- HTTPS の中身は見ません
- method / path / header 単位では絞れません
- 認証系 endpoint や、MITM したくない host をここに置きます

### `requestFiltering.allowRules`

inspect 済み request に対する allow ルールです。

```json
{
  "requestFiltering": {
    "allowRules": [
      {
        "name": "aws eks list-clusters",
        "methods": ["GET"],
        "protocols": ["https"],
        "hosts": ["eks.ap-northeast-1.amazonaws.com"],
        "pathPatterns": ["/clusters*"]
      }
    ]
  }
}
```

特徴:

- `hosts` に書いた host は自動で inspect 対象になります
- その host の request を method / path / protocol / header 単位で allow できます
- HTTPS の CRUD 制御をしたいときはここを使います

### `requestFiltering.inspectFallbackAllowedMethods`

`allowRules` にも `passthroughHosts` にも載っていない unknown host に対する既定動作です。

```json
{
  "requestFiltering": {
    "inspectFallbackAllowedMethods": []
  }
}
```

おすすめは `[]` です。

- `[]`
  unknown host は block
- `["GET"]`
  unknown host は MITM され、GET だけ通る

運用をわかりやすくしたいなら `[]` の strict mode が安全です。

ただし運用方針として「未指定 host はとりあえず MITM して GET だけ通す」にしたいなら、`["GET"]` も使えます。

このときの優先順位はこうです。

- `tls.passthroughHosts` に入った host は passthrough
- `requestFiltering.allowRules[].hosts` に入った host は rule 優先
- どちらにも入っていない host だけ fallback GET が効く

## ルールの優先順位

HTTPS の CONNECT は次の順で判定されます。

1. `tls.passthroughHosts` に一致すれば passthrough
2. `requestFiltering.allowRules[].hosts` に一致すれば inspect
3. `inspectFallbackAllowedMethods` が非空なら inspect fallback
4. どれにも当たらなければ block

つまり、同じ host を両方に書いたときは `passthroughHosts` が優先です。
また、rule がある host では fallback GET より rule が優先です。

## 例: AWS を GET だけ通す

SSO refresh 系は passthrough、EKS API は inspect して `GET /clusters` だけ許可する例です。

```json
{
  "tls": {
    "passthroughHosts": [
      "oidc.ap-northeast-1.amazonaws.com",
      "ap-northeast-1.signin.aws.amazon.com",
      "portal.sso.ap-northeast-1.amazonaws.com",
      "sts.ap-northeast-1.amazonaws.com"
    ]
  },
  "requestFiltering": {
    "inspectFallbackAllowedMethods": [],
    "allowRules": [
      {
        "name": "aws eks list-clusters",
        "methods": ["GET"],
        "protocols": ["https"],
        "hosts": ["eks.ap-northeast-1.amazonaws.com"],
        "pathPatterns": ["/clusters*"]
      }
    ]
  }
}
```

この場合:

- `oidc.*` は CA 不要で passthrough
- `eks.*` は MITM されるので CA trust が必要
- `GET /clusters` だけ通る

## AWS profile ごとの passthrough

特定 profile だけ AWS host を素通ししたい場合は、`aws` セクションを使います。

```json
{
  "aws": {
    "enabled": true,
    "profileSelector": {
      "type": "proxyBasicAuth",
      "username": "aws"
    },
    "profilePassthrough": {
      "profiles": ["prod-admin", "breakglass"],
      "onMissingProfile": "inspect"
    }
  }
}
```

前提:

- proxy は `AWS_PROFILE` を直接は見えません
- HTTPS は `CONNECT` 時点で passthrough か MITM かを決める必要があります
- そのため、client 側から selector を proxy URL で渡します

使い方:

```bash
export HTTPS_PROXY=http://aws:${AWS_PROFILE}@127.0.0.1:8787
export HTTP_PROXY="$HTTPS_PROXY"
```

このとき:

- `aws` が selector username
- `${AWS_PROFILE}` が proxy に渡す profile 名
- `profiles` に一致した AWS host は passthrough
- 一致しない profile は既存ルールで inspect
- `onMissingProfile=block` にすると selector なし AWS 通信を拒否

## 導入の最短手順

1. `mitmdump` を 1 回起動して CA を生成する
2. `./install-ca.sh` で system trust store に登録する
3. `proxy.config.json` を編集する
4. proxy を起動する
5. 必要なら `AWS_CA_BUNDLE` や `NODE_EXTRA_CA_CERTS` を追加する

最短コマンド:

```bash
cd ~/codex-proxy/mitmproxy-proxy
./start.sh
./install-ca.sh
```

別シェルで:

```bash
export HTTP_PROXY=http://127.0.0.1:8787
export HTTPS_PROXY=http://127.0.0.1:8787
export ALL_PROXY=http://127.0.0.1:8787
```
