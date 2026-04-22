# AWS Profile Passthrough Design

## 目的

この `mitmproxy-proxy` で AWS 向け通信だけ特別扱いし、特定の AWS profile に紐づくアクセスだけ `passthrough` できるようにする。

想定ユースケース:

- 普段の AWS API は従来どおり inspect / allow rule / fallback で制御したい
- ただし `prod-admin` や `breakglass` のような一部 profile だけは MITM せず素通ししたい
- AWS 以外の host 判定ロジックは極力既存のままにしたい

## まず押さえる制約

proxy はネットワーク通信しか見えないので、AWS CLI の `--profile` や `AWS_PROFILE` はそのままでは観測できない。

特に HTTPS は `CONNECT` の時点で `passthrough` か `MITM` かを決める必要がある。`CONNECT` 後の HTTP header や SigV4 を見てから切り替えるのは遅い。

つまり、この機能を成立させるには:

1. クライアントが `CONNECT` 時点で profile を proxy に渡す
2. proxy がその profile を使って AWS host だけ特別判定する

この 2 点が必要。

## 採用方針

AWS profile の受け渡しは `Proxy-Authorization` の Basic 認証を流用する。

具体例:

```text
HTTPS_PROXY=http://aws:prod-admin@127.0.0.1:8787
```

このとき proxy は:

- username が `aws` なら AWS profile selector とみなす
- password の `prod-admin` を profile 名として扱う
- これは認証ではなくローカル proxy への選択ヒントとして扱う

この方式を採る理由:

- `CONNECT` request header で受け取れる
- AWS CLI / botocore 側に大きな変更を入れずに使える
- plain HTTP と HTTPS の両方で同じ受け渡し方法にできる
- `X-...` 系 custom header と違って TLS 開始前に見える

## スコープ

この拡張は generic な「任意サービスの profile ルーティング」にはしない。AWS 専用の設定ブロックとして追加する。

理由:

- ユーザー要件が AWS に限定されている
- AWS host 群はある程度まとまったパターンで判定できる
- 既存 schema への影響を小さくできる

## 設定スキーマ案

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
      "hostPatterns": [
        "*.amazonaws.com",
        "*.amazonaws.com.cn",
        "*.api.aws",
        "*.signin.aws.amazon.com"
      ],
      "onMissingProfile": "inspect"
    }
  }
}
```

### 各項目

- `aws.enabled`
  AWS 特別処理の有効化フラグ。未指定時は `false`
- `aws.profileSelector.type`
  初期実装では `proxyBasicAuth` 固定
- `aws.profileSelector.username`
  selector とみなす Basic username。推奨値は `aws`
- `aws.profilePassthrough.profiles`
  passthrough 対象にしたい AWS profile 名の配列
- `aws.profilePassthrough.hostPatterns`
  AWS 特別判定を適用する host glob。未指定時は上記 default を使う
- `aws.profilePassthrough.onMissingProfile`
  selector がない AWS 通信に対する挙動
  `inspect` または `block`

## 互換性

既存 config との後方互換は維持する。

- `aws` セクションがなければ現行挙動のまま
- `aws.enabled=false` なら現行挙動のまま
- AWS host でも profile selector が無ければ `onMissingProfile=inspect` の場合は現行ロジックへフォールバック

## 判定優先順位

AWS 特別処理を入れたあとの優先順位は次を推奨する。

### CONNECT / TLS 判定

1. `tls.passthroughHosts` に一致したら passthrough
2. AWS host かつ selector profile が `aws.profilePassthrough.profiles` に一致したら passthrough
3. `requestFiltering.allowRules[].hosts` に一致したら MITM
4. `inspectFallbackAllowedMethods` が非空なら MITM fallback
5. どれにも当たらなければ block

### HTTP request 判定

1. `tls.passthroughHosts` に一致した host は allow 扱い
2. AWS host かつ selector profile が passthrough 対象なら allow 扱い
3. `allowRules` を評価
4. fallback method を評価
5. それ以外は block

この順序にすることで:

- 明示的な static passthrough が最優先
- AWS profile passthrough は allow rule より強い
- 既存 allow rule / fallback の意味はなるべく維持

## 実装ポイント

既存コード上の主な変更点は `addon.py` の以下。

- `load_config`
- `evaluate_connect`
- `evaluate_request`
- `CodexProxy.http_connect`
- `CodexProxy.tls_clienthello`
- `CodexProxy.request`
- `client_disconnected` の追加

### 1. config 読み込み

`load_config()` に `aws` セクションの validation と default 補完を追加する。

追加で必要な helper:

- `get_optional_string`
- `get_optional_bool`
- `validate_enum`

### 2. AWS host 判定

新規 helper を追加する。

```python
def is_aws_host(hostname: str, config: dict[str, Any]) -> bool:
    ...
```

これで `aws.profilePassthrough.hostPatterns` を評価する。

### 3. profile selector 抽出

`Proxy-Authorization` を安全に読む helper を追加する。

```python
def extract_aws_profile_from_proxy_auth(
    headers: dict[str, str], config: dict[str, Any]
) -> Optional[str]:
    ...
```

仕様:

- `Proxy-Authorization: Basic ...` のみ対象
- decode 後の `username:password` を split
- `username == config["aws"]["profileSelector"]["username"]` の場合のみ有効
- password を profile 名として返す
- 壊れた値は `None`
- raw header や password 全体は log しない

### 4. CONNECT 時点の判定キャッシュ

`tls_clienthello()` では request header が見えないため、`http_connect()` で selector を解釈して接続単位の decision をキャッシュする必要がある。

推奨キャッシュ key:

```python
(flow.client_conn.id, hostname, port)
```

理由:

- mitmproxy の `Client` connection には一意な `id` がある
- 同一 client connection 上で複数 CONNECT がありえても host/port を足せば衝突しにくい

保持内容:

```python
{
  "action": "passthrough" | "mitm" | "block",
  "reason": "...",
  "awsProfile": "prod-admin" | None,
  "expiresAt": ...
}
```

### 5. `http_connect()` の処理

`flow.request.headers` から selector profile を取り出し、AWS 特別判定込みで `evaluate_connect()` を呼ぶ。

ここでやること:

- profile 取得
- decision 算出
- `(client_conn.id, host, port)` に decision 保存
- `block` なら 403 を返す
- log には `awsProfile=<name>` を必要最小限で含める

### 6. `tls_clienthello()` の処理

`data.context.client.id` と `data.context.server.address` で cache を引く。

- cache に `passthrough` があれば `data.ignore_connection = True`
- cache が無ければ既存の host ベース `evaluate_connect()` へフォールバック

これで profile selector を `CONNECT` から TLS 判定へ橋渡しできる。

### 7. `request()` の処理

plain HTTP の AWS request や、安全側の再評価用に request 時点でも AWS 判定を使えるようにする。

ただし HTTPS passthrough については request event 自体が来ないので、主判定はあくまで `http_connect()` / `tls_clienthello()` に置く。

### 8. cache 掃除

`client_disconnected()` を追加して、該当 `client.id` の cache を削除する。

加えて TTL でも掃除できるようにしておくと安全。

## `evaluate_connect()` の拡張イメージ

概念的には、既存の host-only 判定を次のように拡張する。

```python
def evaluate_connect(
    hostname: str,
    port: int,
    config: dict[str, Any],
    aws_profile: Optional[str] = None,
) -> dict[str, Any]:
    ...
```

ロジック:

1. static `tls.passthroughHosts`
2. `is_aws_host(hostname)` かつ `aws_profile in passthroughProfiles`
3. `allowRules` に host match
4. fallback
5. block

`evaluate_request()` も同様に `aws_profile` を optional で受け取る形に揃えるとよい。

## ログ方針

ログはデバッグには使いたいが、秘匿情報は出さない。

出してよいもの:

- `awsProfile=prod-admin`
- `selector=proxy-basic-auth`
- `reason="aws profile passthrough: prod-admin"`

出さないもの:

- `Proxy-Authorization` raw 値
- Basic password 全体

## クライアント側の使い方

実運用では wrapper を 1 つ用意するのがよい。

例:

```bash
#!/usr/bin/env bash
set -euo pipefail

profile="${AWS_PROFILE:-default}"
proxy_host="${CODEX_PROXY_HOST:-127.0.0.1}"
proxy_port="${CODEX_PROXY_PORT:-8787}"

export HTTPS_PROXY="http://aws:${profile}@${proxy_host}:${proxy_port}"
export HTTP_PROXY="$HTTPS_PROXY"

exec aws "$@"
```

これで profile ごとに proxy へ selector を渡せる。

例:

```bash
AWS_PROFILE=prod-admin ./aws-via-proxy sso login
AWS_PROFILE=dev ./aws-via-proxy eks list-clusters
```

## エラー時の挙動

推奨:

- selector なし: `onMissingProfile=inspect`
- selector username 不一致: selector なし扱い
- Basic decode 失敗: selector なし扱い
- AWS host ではない: 既存ロジック

strict にしたい環境では `onMissingProfile=block` を選べるようにする。

## テスト観点

### unit test

- `extract_aws_profile_from_proxy_auth()` の正常系
- malformed Basic header
- username 不一致
- AWS host 判定
- `evaluate_connect(..., aws_profile="prod-admin")`
- `evaluate_connect(..., aws_profile="dev")`
- `onMissingProfile=inspect/block`

### 手動確認

1. `HTTPS_PROXY=http://127.0.0.1:8787` では現行どおり inspect される
2. `HTTPS_PROXY=http://aws:prod-admin@127.0.0.1:8787` では AWS host が passthrough される
3. 同条件でも AWS 以外 host は現行ルールのまま
4. `tls.passthroughHosts` にある host は profile に関係なく passthrough
5. `allowRules` 対象 host でも passthrough profile なら MITM されない

## 非目標

今回やらないもの:

- request body や SigV4 署名から profile を推定する
- AWS profile を upstream server 側へ伝搬する
- 汎用的な user/group/tenant ベースルーティング
- proxy 自体の本格的な認証機能

## 採用判断

この設計のいちばん大事な点は、「profile 判定を proxy の外で暗黙推定しない」こと。

profile を `CONNECT` 時点で明示的に渡す前提にすると:

- passthrough 判定が TLS 前に完結する
- AWS 専用の例外処理としてロジックを閉じ込めやすい
- 既存 host/method ベースルールへの影響が小さい

逆に、profile を渡さないまま proxy 側だけで推定しようとすると、HTTPS passthrough の要件と衝突しやすい。
