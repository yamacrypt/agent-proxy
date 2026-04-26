# mitmproxy-proxy

AI Agent や CLI ツールの外部通信を、ローカルで観測・制御するための `mitmproxy` addon です。

HTTP/HTTPS proxy として動かし、通信先や request 内容に応じて次のように扱います。

- `passthrough`: TLS を MITM せず、そのまま通す
- `inspect`: HTTPS を MITM して request rule を評価する
- `block`: 許可していない通信を拒否する

AI Agent に外部通信を許しつつ、「どこへ出ているか分かる」「必要な通信だけ通す」「MITM すると壊れる endpoint は触らない」という運用をするための小さなローカル proxy です。

## できること

- `mitmproxy` / `mitmdump` 上で動く
- JSON config で通信ルールを書ける
- host / method / path / header で inspected request を allow できる
- MITM したくない host を TLS passthrough できる
- 未知 host の fallback 許可 method を指定できる
- Proxy Basic auth を selector として使い、条件付き passthrough できる
- config を hot reload する
- 設定が効いているかを unit test で確認できる

## セットアップ

依存を入れます。

```bash
python3 -m pip install -r requirements.txt
```

proxy を起動します。

```bash
./start.sh
```

デフォルトでは `127.0.0.1:8787` で待ち受けます。

別 shell で、使いたい command に proxy を向けます。

```bash
export HTTP_PROXY=http://127.0.0.1:8787
export HTTPS_PROXY=http://127.0.0.1:8787

curl https://example.com
```

background で起動する場合:

```bash
./background.sh
```

## HTTPS inspect と CA

`inspect` する HTTPS 通信では、`mitmproxy` が接続先 host 用の証明書を動的に発行します。そのため、client 側が `mitmproxy` の CA を信頼している必要があります。

CA は `mitmdump` 初回起動時に `~/.mitmproxy/` に作られます。

Ubuntu / WSL では次で system trust store に登録できます。

```bash
./install-ca.sh
```

中では概ね次を実行しています。

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

一部の tool は system trust store を見ません。その場合は個別に CA を指定します。

```bash
export SSL_CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export REQUESTS_CA_BUNDLE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
export NODE_EXTRA_CA_CERTS="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
```

AWS CLI v2 では `~/.aws/config` に `ca_bundle` を書くほうが安定することがあります。

```ini
[default]
region = ap-northeast-1
ca_bundle = /etc/ssl/certs/ca-certificates.crt
```

## 設定ファイル

設定は [config/proxy.config.json](config/proxy.config.json) に書きます。

最小構成はこのような形です。

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "tls": {
    "passthroughHosts": ["api.openai.com", "github.com", "*.github.com"]
  },
  "requestFiltering": {
    "inspectFallbackAllowedMethods": ["GET"],
    "allowRules": []
  },
  "conditionalPassthrough": []
}
```

### `tls.passthroughHosts`

ここに入れた host は MITM せず、そのまま通します。

認証系 endpoint、package registry、MITM する必要がない API などを入れます。

```json
{
  "tls": {
    "passthroughHosts": [
      "api.openai.com",
      "auth.openai.com",
      "github.com",
      "*.github.com",
      "*.githubusercontent.com"
    ]
  }
}
```

### `requestFiltering.allowRules`

MITM して inspect した request に対する allow rule です。

`allowRules[].hosts` に書いた host は inspect 対象になります。その host への request は、allow rule に一致したものだけ通ります。

```json
{
  "requestFiltering": {
    "allowRules": [
      {
        "name": "aws eks list clusters",
        "methods": ["GET"],
        "protocols": ["https"],
        "hosts": ["eks.ap-northeast-1.amazonaws.com"],
        "pathPatterns": ["/clusters*"]
      }
    ]
  }
}
```

主な match field:

- `methods`
- `protocols`
- `hosts`
- `ports`
- `pathPatterns`
- `urlPatterns`
- `userAgents`
- `headerPatterns`

文字列の pattern では `*`、`**`、`?` が使えます。

### `requestFiltering.inspectFallbackAllowedMethods`

`passthroughHosts` にも `allowRules` にもない unknown host の fallback です。

```json
{
  "requestFiltering": {
    "inspectFallbackAllowedMethods": ["GET"]
  }
}
```

`["GET"]` なら unknown host は inspect され、GET だけ通ります。

より厳しくするなら空配列にします。

```json
{
  "requestFiltering": {
    "inspectFallbackAllowedMethods": []
  }
}
```

### `conditionalPassthrough`

client 側の文脈に応じて passthrough したいときに使います。

例として、proxy は `AWS_PROFILE` を直接見られません。そこで Proxy Basic auth の password 部分を selector として使います。

```bash
export HTTPS_PROXY=http://aws:${AWS_PROFILE}@127.0.0.1:8787
export HTTP_PROXY="$HTTPS_PROXY"
```

設定例:

```json
{
  "conditionalPassthrough": [
    {
      "name": "aws-profile",
      "hostPatterns": [
        "*.amazonaws.com",
        "*.amazonaws.com.cn",
        "*.api.aws",
        "*.signin.aws.amazon.com"
      ],
      "selector": {
        "type": "proxyBasicAuth",
        "username": "aws",
        "allowedPasswords": ["prod-*", "breakglass"]
      },
      "onMissingSelector": "inspect"
    }
  ]
}
```

この場合:

- `username` が `aws` の Basic auth だけ selector として扱う
- password 部分を local selector value として扱う
- `allowedPasswords` に一致した host は passthrough する
- 一致しない場合は通常の inspect / allowRules / fallback に流す
- `Proxy-Authorization` は upstream に流す前に削除する

これは本格的な proxy 認証ではなく、ローカル proxy に対する routing hint です。

## 判定順

HTTPS CONNECT では次の順で判定します。

1. `tls.passthroughHosts` に一致したら `passthrough`
2. `conditionalPassthrough` に一致したら `passthrough`
3. `allowRules[].hosts` に一致したら `inspect`
4. `inspectFallbackAllowedMethods` が空でなければ `inspect`
5. それ以外は `block`

inspect された HTTP request は次の順で判定します。

1. passthrough host は allow
2. conditional passthrough に一致したら allow
3. allow rule に一致したら allow
4. 明示 rule のない host では fallback method を allow
5. それ以外は block

`tls.passthroughHosts` が最優先です。MITM すると壊れる host はここに入れておくのが基本です。

## テスト

```bash
python3 -m unittest -v
```

config 読み込み、rule 評価、conditional passthrough、実際の `config/proxy.config.json` の挙動をテストしています。

## 注意

これはローカル開発用の proxy であり、完全な network sandbox ではありません。

この proxy を通るように設定された通信は観測・制御できますが、process が別経路で通信できる環境では、この proxy だけで外部通信を完全に防ぐことはできません。必要なら OS、container、firewall、sandbox などと組み合わせてください。

また、`~/.mitmproxy/mitmproxy-ca.pem` には CA の秘密鍵が含まれます。公開したり共有したりしないでください。

## 関連

- [zenn-agent-proxy.md](zenn-agent-proxy.md): Zenn 記事の下書き
