# クライアント連携

このガイドでは、Web アプリケーション（RP: Relying Party）が Kagi Identity を IdP として利用する手順を説明します。本番アプリでは、メンテナンスされている OIDC クライアントライブラリの利用を推奨します。組み込み SDK は最小限のデモ用であり、自前の認証ロジックを実装する際は自分の脅威モデルと照合してください。

## 1. クライアントを登録する

コールバック URI は**完全一致**で登録します。スキーム、ホスト、ポート、パス、末尾スラッシュまで一致させる必要があります。ワイルドカードは使用できません。

ローカルデモでは `demo-web` が自動登録されます。新しいパブリッククライアントは、管理トークンで保護された動的クライアント登録エンドポイント（`POST /register`）で登録します。

```bash
export KAGI_REGISTRATION_TOKEN='秘密管理領域から取得した値'
curl --fail-with-body --request POST 'https://id.example.com/register' \
  --header "Authorization: Bearer $KAGI_REGISTRATION_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{
    "client_name": "Example Web App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access",
    "token_endpoint_auth_method": "none"
  }'
```

- `token_endpoint_auth_method` は `none`（パブリック）、`client_secret_basic`、`client_secret_post`、`private_key_jwt` のいずれかです。
- `private_key_jwt` を使う場合は、秘密鍵を含まない**公開 JWK Set** を `jwks` にインラインで指定します。`jwks_uri` は SSRF 回避のため受け付けません。
- `redirect_uris` は HTTPS 必須です。HTTP は `localhost`、`127.0.0.0/8`、`::1` などの実際のループバックホストに限り許可されます。`http://localhost.evil.example` のような紛らわしいホストは拒否されます。
- `scope` には `openid` が必須です。
- `client_name` は 1〜120 文字の印刷可能文字です。

登録レスポンスは機密情報として扱ってください。クライアントシークレットが発行された場合、ログに残さないでください。

パブリッククライアント（ブラウザー / モバイル）はシークレットを秘匿できないため、**Authorization Code + PKCE（S256）** を必ず使用します。機密クライアントは信頼できるバックエンドでトークン交換を行い、対応するクライアント認証方式を使ってください。

## 2. ブラウザー SDK の最小例

Kagi Identity のオリジンから SDK を読み込みます。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<button id="sign-in" type="button">サインイン</button>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  document.querySelector("#sign-in").addEventListener("click", () => {
    Kagi.login();
  });
</script>
```

コールバックルートでは、同じ issuer / clientId / redirectUri を設定してからコールバックを処理します。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  (async () => {
    const session = await Kagi.handleCallback();
    const profile = await Kagi.userinfo();
    // アプリに必要なプロフィール項目だけを描画する
    console.log({ subject: profile.sub, session });
  })();
</script>
```

SDK の API は変更される可能性があります。デプロイするコミットの `/demo` と `static/kagi.js` を確認してください。コールバックが成功しただけでは不十分です。アプリケーションに必要なトークン検証とプロトコル要件を必ず実施してください。

## 3. Discovery と署名鍵

エンドポイントをハードコードせず、Discovery ドキュメントから取得します。

```bash
curl --fail 'https://id.example.com/.well-known/openid-configuration'
curl --fail 'https://id.example.com/jwks.json'
```

- `issuer` は設定した公開 Issuer と完全一致する必要があります。
- JWKS は RP ライブラリの指針に従ってキャッシュし、未知の `kid` に遭遇したら再取得できるようにします。単一の署名鍵を無期限にピン留めしないでください。
- ID トークンは、署名、`iss`、`aud`（自分の client_id）、`exp`、`nonce`、`state` を検証します。
- アクセストークンは UserInfo などの保護リソースで検証されます。RP 側で JWT を独自検証する場合も `typ`、`iss`、`aud`、期限を確認してください。

### Discovery で確認できる主なメタデータ

| 項目 | 内容 |
| --- | --- |
| `issuer` | 公開 Issuer |
| `authorization_endpoint` / `token_endpoint` | 認可・トークンエンドポイント |
| `pushed_authorization_request_endpoint` | PAR エンドポイント（RFC 9126） |
| `code_challenge_methods_supported` | `S256` のみ |
| `acr_values_supported` | `urn:kagi:acr:passkey` / `urn:kagi:acr:recovery` |
| `prompt_values_supported` | `none` / `login` / `consent` / `select_account` |
| `claims_parameter_supported` | `false`（`claims` パラメーターは未実装） |

## 4. 認可リクエストの例

```text
GET https://id.example.com/authorize?
  client_id=YOUR_CLIENT_ID
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=RANDOM_STATE
  &nonce=RANDOM_NONCE
  &code_challenge=BASE64URL_SHA256_OF_VERIFIER
  &code_challenge_method=S256
```

PAR を使う場合は、まず `POST /par` に同じパラメーターを送り、返却された `request_uri` を `/authorize` に渡します。`KAGI_REQUIRE_PAR=1` の環境では PAR が必須です。

DPoP を使う場合は、`/par` と `/token` の両方に `DPoP` ヘッダーで証明を付けます。トークン応答の `token_type` は `DPoP` になり、`/userinfo` では `ath`（アクセストークンのハッシュ）を含む証明が必要です。

## 5. リダイレクトとトークンの安全性

- redirect URI は完全一致で登録し、ワイルドカードを使わない。
- Authorization Code + PKCE（S256）を使い、Implicit フローを使わない。
- `state` と `nonce` は暗号学的にランダムな値にし、コールバックで検証する。
- トークンをクエリ文字列、分析イベント、アプリケーションログに含めない。
- 長期間有効な資格情報をブラウザーから読める永続ストレージに置かない。
- アクセストークンは短命にし、必要なスコープだけを要求する。
- サーバー側セッションを使う場合、トークンはバックエンドに保持し、アプリのセッション Cookie には `Secure`、`HttpOnly`、適切な `SameSite` を設定する。
- 認可コードは 1 回しか使えない。交換に失敗した場合も、同じコードを再利用しない。
- リフレッシュトークンはローテーションされる。古いトークンを再利用するとファミリー全体が失効する。

組み込み SDK は評価用の便宜的な手段であり、本番の認証ロジックを手書きすることを推奨するものではありません。
