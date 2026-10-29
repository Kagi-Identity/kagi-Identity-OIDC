# kagi — a passkey-first OpenID Provider

`kagi` は **パスキー (WebAuthn) だけ**で認証する OpenID Connect Provider の参照実装です。
パスワードもメール認証も持ちません。OAuth 2.1 と FAPI 2.0 の主要プロファイル
(DPoP / PAR / JAR / JARM) を実装し、署名鍵は ES256、保存トークンはすべてハッシュ化しています。

```
┌────────────┐   1. PAR (signed + DPoP)   ┌───────────────────────┐
│  Relying   │ ─────────────────────────▶ │  kagi                 │
│  Party     │ ◀───────────────────────── │  /par /authorize      │
│            │   2. request_uri           │  /token /userinfo     │
│            │                            │  /jwks.json           │
│            │   3. passkey (WebAuthn)    │                       │
│  Browser   │ ◀────────────────────────▶ │  SQLite / Supabase    │
└────────────┘                            └───────────────────────┘
```

## 特長

| 領域 | 実装 |
| --- | --- |
| 認証 | WebAuthn Level 2/3 パスキー、discoverable credential、conditional UI、attestation (`none` / `packed` self-attestation)、署名カウンタによるクローン検知、BE/BS フラグ |
| 認可 | Authorization Code + PKCE (S256 必須)、`prompt=none/login/consent`、同意の記憶、`max_age`、`state`、`nonce`、RFC 9207 `iss` |
| FAPI 2.0 | **PAR** (RFC 9126)、**DPoP** (RFC 9449, `cnf.jkt` + `ath` + `jti` リプレイ対策)、**JAR** (RFC 9101, `request`)、**JARM** (`response_mode=jwt/query.jwt/fragment.jwt`) |
| クライアント認証 | `client_secret_basic` / `client_secret_post` / `private_key_jwt` (RS256/PS256/ES256/EdDSA) / public client |
| トークン | ES256 JWT access token (`typ: at+jwt`)、refresh token ローテーション + 再利用検知 (family 失効)、`at_hash`、`sid` |
| エンドポイント | discovery / jwks / authorize / par / token / userinfo / introspect / revoke / end_session / register (RFC 7591) |
| 保存先 | SQLite (既定) と **PostgreSQL / Supabase** のデュアルバックエンド。`KAGI_DATABASE_URL` を設定するだけで切り替わる |
| 導線 | 組み込みブラウザ SDK (`/static/kagi.js`)、デモ RP (`/demo`)、CORS 対応の API、`supabase/schema.sql` |
| 鍵管理 | 起動時に ES256 鍵を自動生成、`/jwks.json` で公開、`/admin/keys/rotate` でローテーション (旧鍵は猶予期間中も公開) |
| 堅牢性 | CSP / HSTS / nosniff / frame-ancestors、HttpOnly + SameSite=Lax セッション、CSRF トークン、全トークンの SHA-256 保存、PKCE 検証、厳密な redirect_uri 一致 |

## クイックスタート

```bash
cp .env.example .env        # もしくは環境変数を直接 export
cargo run --release
# → http://localhost:8080
```

初回起動で SQLite (`kagi.db`) と署名鍵が作られます。
`KAGI_SEED_DEMO=1` のとき、動作確認用の public client `demo-web`
(redirect: `http://localhost:3000/callback` と `/demo/callback`) が登録されます。

1. <http://localhost:8080/signup> でユーザー名を入力 → 「パスキーを作成」
2. 端末の生体認証 / PIN でパスキーを作成
3. アカウント画面で「パスキーを追加」「サインアウト」が可能
4. <http://localhost:8080/demo> で組み込み用 SDK の動作を確認
5. <http://localhost:8080/.well-known/openid-configuration> でメタデータを確認

> パスキーは secure context でのみ動作します。`localhost` は例外的に許可されますが、
> LAN の IP や独自ドメインで動かす場合は必ず HTTPS  terminate してください
> (`KAGI_ISSUER=https://id.example.com`, `KAGI_RP_ID=example.com`)。

## 設定

| 変数 | 既定値 | 説明 |
| --- | --- | --- |
| `KAGI_ISSUER` | `http://localhost:8080` | OP の公開オリジン (末尾スラッシュなし) |
| `KAGI_BIND` | `127.0.0.1:8080` | 待ち受けアドレス |
| `KAGI_RP_ID` | issuer のホスト | WebAuthn RP ID (登録可能ドメイン) |
| `KAGI_RP_NAME` | `kagi` | パスキー UI に表示される名前 |
| `KAGI_ORIGIN` | issuer | clientDataJSON の origin 検証値 |
| `KAGI_DB` | `kagi.db` | SQLite ファイル (PostgreSQL 未使用時) |
| `KAGI_DATABASE_URL` | (なし) | PostgreSQL / Supabase の接続文字列。設定すると SQLite より優先 |
| `KAGI_ALLOW_SIGNUP` | `1` | セルフサインアップの可否 |
| `KAGI_SEED_DEMO` | `0` | デモクライアントを作る |
| `KAGI_REQUIRE_PAR` | `0` | 全クライアントに PAR を強制 (FAPI 2.0 モード) |
| `KAGI_REQUIRE_DPOP` | `0` | 全クライアントに DPoP を強制 |
| `KAGI_ADMIN_TOKEN` | (なし) | 鍵ローテーションの Bearer トークン。未設定なら endpoint は 404 |
| `KAGI_REGISTRATION_TOKEN` | (なし) | 動的クライアント登録の初期アクセストークン |
| `KAGI_SESSION_TTL` | `28800` | ブラウザセッション (秒) |
| `KAGI_CODE_TTL` | `60` | 認可コード (秒) |
| `KAGI_ACCESS_TTL` | `300` | アクセストークン (秒) |
| `KAGI_REFRESH_TTL` | `2592000` | リフレッシュトークン (秒) |
| `KAGI_PAR_TTL` | `90` | `request_uri` (秒) |

`KAGI_REQUIRE_PAR=1 KAGI_REQUIRE_DPOP=1` にすると、PAR + PKCE + DPoP を必須にする
FAPI 2.0 相当の厳格モードになります。

## エンドポイント

| Path | 説明 |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 メタデータ |
| `GET /jwks.json` | 公開鍵 (JWK Set) |
| `GET /authorize` | 認可エンドポイント (PAR / JAR 対応) |
| `POST /par` | Pushed Authorization Request |
| `POST /token` | コード交換 / リフレッシュ / client_credentials |
| `GET/POST /userinfo` | UserInfo (DPoP-bound token 対応) |
| `POST /introspect` | RFC 7662 |
| `POST /revoke` | RFC 7009 |
| `GET/POST /logout` | RP-initiated logout |
| `POST /register` | 動的クライアント登録 |
| `POST /admin/keys/rotate` | 署名鍵ローテーション |
| `GET /demo` | デモ RP (組み込み SDK の実例) |
| `GET /static/kagi.js` | 任意のサイトに貼るブラウザ SDK |

## 他のサイトへの導入

kagi は「自前のログイン基盤」として任意のサイトから使えます。もっとも簡単な方法は
同梱のブラウザ SDK です。Authorization Code + PKCE (S256)、`state` / `nonce` の検証、
トークン交換、UserInfo 取得までを 2 つのスクリプトで済ませられます。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",   // kagi の公開オリジン
    clientId: "your-client-id",         // /register で登録した client_id
    redirectUri: location.origin + "/callback",
    scope: "openid profile email",
  });
  document.querySelector("#login").onclick = () => Kagi.login();
</script>
```

コールバックページ (`/callback`) では次のように受け取ります。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({ issuer: "https://id.example.com", clientId: "your-client-id",
                   redirectUri: location.origin + "/callback" });
  const session = await Kagi.handleCallback(); // state/nonce を検証しコード交換
  const user = await Kagi.userinfo();          // sub / name / email …
  console.log(user);
</script>
```

- `Kagi.login()` — 認可エンドポイントへ遷移 (PKCE チャレンジを生成)
- `Kagi.handleCallback()` — `code` を交換し、ID トークンの `iss` / `aud` / `nonce` を検証
- `Kagi.userinfo()` / `Kagi.refresh()` / `Kagi.logout()`
- トークンは `sessionStorage` にだけ保存 (localStorage には置かない)

### クライアント登録

公開クライアント (SPA / 静的サイト) は `auth_method: none`、`grant_types: ["authorization_code"]`
で登録し、`redirect_uris` にコールバック URL を**完全一致**で登録してください。

```bash
curl -s -X POST https://id.example.com/register \
  -H "Authorization: Bearer $KAGI_REGISTRATION_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "client_name": "My Site",
    "redirect_uris": ["https://example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access",
    "auth_method": "none"
  }'
```

サーバー間で使う場合は `client_secret_basic` か `private_key_jwt` を選び、トークン交換を
サーバー側で行ってください。`/token`・`/userinfo`・`/par` など API は CORS (`*`) と
`OPTIONS` プリフライトに対応しています。ID トークンの署名検証は RP 側 (サーバー) で
`/jwks.json` を使って行うのが推奨です。

## Supabase (PostgreSQL) を使う

`KAGI_DATABASE_URL` を設定すると、保存先が Supabase の Postgres に切り替わります。
SQLite 用のコードパスはそのまま残るため、ローカル開発は SQLite、本番は Supabase という
使い分けができます。

1. Supabase でプロジェクトを作成し、**Connection string** (Session pooler もしくは Direct)
   を取得します。TLS 必須なので `sslmode=require` を付けます。
2. 環境変数を設定して起動します。テーブルは `supabase/schema.sql` から自動適用されます。

```bash
export KAGI_DATABASE_URL='postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require'
export KAGI_ISSUER=https://id.example.com
cargo run --release
# [kagi] database postgres
```

- スキーマは `supabase/schema.sql` が単一の情報源です (手動適用も可能)。
- 真偽値は SQLite と共通の SQL で扱うため `BIGINT` (0/1) で保存します。
- kagi は **service role / postgres ユーザー**で接続し、RLS を経由せずにテーブルを
  読み書きします。Supabase の anon / authenticated キーでテーブルを直接公開しないでください。
- 署名鍵も DB に保存されるため、DB のバックアップには鍵が含まれます。本番では
  KMS/HSM への移行を検討してください。
- 単一プロセス前提の設計 (プロセス内 Mutex) は Postgres でも同じです。複数インスタンスで
  動かす場合は、セッション/リプレイキャッシュの共有化を追加してください。

## 認可コードフローの例 (curl)

`demo-web` は public client なので PKCE だけで動きます。

```bash
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# 1. PAR
curl -s -X POST http://localhost:8080/par \
  -d client_id=demo-web \
  -d response_type=code \
  -d redirect_uri=http://localhost:3000/callback \
  -d scope="openid profile email offline_access" \
  -d state=xyz \
  -d nonce=n-123 \
  -d code_challenge="$CHALLENGE" \
  -d code_challenge_method=S256
# {"request_uri":"urn:ietf:params:oauth:request_uri:...","expires_in":90}

# 2. ブラウザで開いてパスキー認証 → /callback?code=...&state=xyz&iss=...

# 3. コード交換
curl -s -X POST http://localhost:8080/token \
  -d grant_type=authorization_code \
  -d client_id=demo-web \
  -d code="<code>" \
  -d redirect_uri=http://localhost:3000/callback \
  -d code_verifier="$VERIFIER"
```

DPoP を使う場合は、`/par`・`/token` に `DPoP: <proof>` を付け、
`token_type` が `DPoP` になり、`/userinfo` にも `ath` 付きの proof が必要になります。

## テスト

`cargo test` は JOSE (署名・検証・thumbprint)、`htu` 正規化、CBOR/COSE パースの
ユニットテストを実行します。エンドツーエンドの確認は `scripts/` の Python
スクリプトで行えます (`requests` と `cryptography` が必要)。

```bash
# 1) コア + JARM/DPoP + WebAuthn (パスワード不要のソフトウェア認証器)
KAGI_SEED_DEMO=1 KAGI_DB=kagi-e2e.db cargo run &
KAGI_DB=kagi-e2e.db python scripts/e2e_oidc.py
KAGI_DB=kagi-e2e.db python scripts/e2e_advanced.py
python scripts/e2e_webauthn.py

# 2) 管理系 (DCR の初期トークン / private_key_jwt / JAR / 鍵ローテーション)
KAGI_SEED_DEMO=1 KAGI_DB=kagi-e2e.db \
KAGI_ADMIN_TOKEN=test-admin KAGI_REGISTRATION_TOKEN=reg-secret cargo run &
python scripts/e2e_admin.py
```

| スクリプト | 対象 |
| --- | --- |
| `e2e_oidc.py` | PAR、同意、PKCE、コード交換、ID token 署名、UserInfo、introspection、RT ローテーションと再利用検知、失効、`prompt=none`、DPoP バインド |
| `e2e_advanced.py` | JARM (`response_mode=query.jwt`)、PAR→コード→トークン間の DPoP キー一致、CORS プリフライト、`max_age=0` |
| `e2e_webauthn.py` | ソフトウェア認証器によるサインアップ/サインイン、origin・type・challenge 検証、署名改ざん・カウンタ巻き戻しの拒否 |
| `e2e_admin.py` | 初期アクセストークン必須の DCR、`private_key_jwt`、アサーションのリプレイ/aud 検証、JAR 署名検証、鍵ローテーション、logout の redirect 検証 |

`e2e_oidc.py` と `e2e_advanced.py` はセッションを直接 DB に投入するため、
サーバと同じ `KAGI_DB` を指定してください。

## 設計メモ

### なぜ client secret が SHA-256 なのか

クライアントシークレットはサーバが 32 バイトの乱数として生成するため、オフライン
総当たりの対象になりません。高エントロピー秘密値には Argon2 より SHA-256 の方が
適切で、認証レイテンシも一定になります。ユーザーのパスワードは存在しません。

### トークンの保存

- 認可コード・リフレッシュトークン・セッション ID は **SHA-256 のみ** を保存
- アクセストークンは JWT だが `jti` を DB に保存し、失効・introspection を可能にする
- 署名鍵は DB に JWK で保存 (参照実装のため。本番は KMS/HSM を推奨)

### DPoP

- `typ=dpop+jwt`、`jwk` (秘密成分なし)、`htm`/`htu`/`iat`/`jti` を検証
- `htu` は issuer を基準に正規化 (プロキシのヘッダに依存しない)
- `jti` は 10 分間リプレイキャッシュ
- 認可コード発行時に `dpop_jkt` を保存し、コード交換時に一致を要求
- アクセストークンと ID token の両方に `cnf.jkt` を付与
- UserInfo はスキームとバインドを厳密に判定する: DPoP バインド済みトークンを
  `Bearer` で提示すると 401、非バインドのトークンを `DPoP` で提示しても 401
  (RFC 9449 §7.1)。proof 欠落・リプレイも 401 + `WWW-Authenticate: DPoP`

### 同意 (consent)

- 同意画面で承認したスコープは `consents` テーブルに保存する
- `prompt=none` は「セッションなし → `login_required`」「同意なし → `consent_required`」
  「両方あり → コード発行」の順で判定する
- 追加スコープを要求された場合は再同意が必要

### WebAuthn

- `residentKey: required` + `userVerification: required`
- rpIdHash / UP / UV / origin / challenge を検証
- ES256 (DER), EdDSA, RS256 の COSE 鍵に対応
- `signCount` が非ゼロで巻き戻った場合はクローンとみなして拒否
- `none` と `packed` self-attestation のみ許可。証明書チェーン付き attestation は
  ポリシー判断が必要なため明示的に拒否

### 制約・今後の拡張

- 単一ノード前提 (プロセス内 Mutex)。PostgreSQL/Supabase を使えば永続化は共有できるが、
  複数インスタンスで動かす場合はセッション/リプレイキャッシュの共有化が必要
- `request_uri` は `urn:ietf:params:oauth:request_uri:*` のみ対応 (SSRF 回避のため
  https の request_uri 取得は行わない)
- back-channel logout / CIBA / SD-JWT VC は未実装
- レート制限はリバースプロキシ側で

## 本番チェックリスト

- [ ] `KAGI_ISSUER` を HTTPS の公開 URL にする
- [ ] `KAGI_RP_ID` を issuer の registrable domain に一致させる
- [ ] `KAGI_REQUIRE_PAR=1`, `KAGI_REQUIRE_DPOP=1` を有効化
- [ ] `KAGI_ADMIN_TOKEN` / `KAGI_REGISTRATION_TOKEN` を設定
- [ ] 本番は `KAGI_DATABASE_URL` で Supabase / PostgreSQL を指定し、バックアップを有効化
- [ ] 署名鍵とトークンを含む DB のバックアップを暗号化して保管
- [ ] 署名鍵を KMS/HSM に移し、`/admin/keys/rotate` を定期実行
- [ ] リバースプロキシでレート制限とボディサイズ制限を設定
- [ ] ログにトークン・コード・クレデンシャルを出さない

## ライセンス

MIT
