//! Server-rendered HTML. No template engine: these are small, auditable pages
//! and every interpolation goes through `esc`.

use crate::db::{Credential, User};
use crate::oidc::split_scope;
use crate::util::esc;
use serde_json::Value;

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title} · kagi</title>
<link rel="stylesheet" href="/static/style.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='7.5' cy='15.5' r='4.5' fill='none' stroke='black' stroke-width='2'/><path d='M10.7 12.3 21 2m-3 3 3 3m-6 0 2 2' fill='none' stroke='black' stroke-width='2'/></svg>">
</head>
<body>
<main class="shell">
{body}
</main>
<script src="/static/app.js" defer></script>
</body>
</html>
"#,
        title = esc(title),
        body = body
    )
}

fn config_script(value: &Value) -> String {
    let raw = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    let safe = raw
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    format!(r#"<script type="application/json" id="kagi-config">{safe}</script>"#)
}

fn brand() -> String {
    r#"<div class="brand"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2m-3 3 3 3m-6 0 2 2"/></svg><span>kagi</span></div>"#.to_string()
}

pub fn error_page(code: &str, message: &str) -> String {
    page(
        "エラー",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">Error {code}</p>
<h1>処理できませんでした</h1>
<p class="muted">{message}</p>
<p class="foot"><a href="/">ホームに戻る</a></p>
</section>"#,
            brand = brand(),
            code = esc(code),
            message = esc(message)
        ),
    )
}

pub fn login_page(rid: &str, csrf: &str) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "login",
        "rid": rid,
        "csrf": csrf,
    }));
    page(
        "サインイン",
        &format!(
            r#"<section class="card narrow">
{brand}
<h1>パスキーでサインイン</h1>
<p class="muted">生体認証・画面ロック・セキュリティキーで認証します。パスワードは保存されません。</p>
<label class="field">
  <span>ユーザー名</span>
  <input id="username" name="username" autocomplete="username webauthn" placeholder="username" autofocus>
</label>
<button class="primary" id="btn-login" type="button">
  <span class="label">パスキーで続行</span>
</button>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<p class="foot">アカウントをお持ちでない方は <a href="/signup{signup_q}">新規登録</a></p>
{config}
</section>"#,
            brand = brand(),
            signup_q = if rid.is_empty() {
                String::new()
            } else {
                format!("?rid={}", crate::util::urlenc(rid))
            },
            config = config
        ),
    )
}

pub fn signup_page(rid: Option<&str>) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "signup",
        "rid": rid,
    }));
    page(
        "新規登録",
        &format!(
            r#"<section class="card narrow">
{brand}
<h1>パスキーで始める</h1>
<p class="muted">アカウントはパスキーだけで保護されます。パスワードもメール認証も不要です。</p>
<form id="signup-form" autocomplete="off">
  <label class="field">
    <span>ユーザー名</span>
    <input id="username" name="username" autocomplete="username" placeholder="alice" required minlength="3" maxlength="64" pattern="[A-Za-z0-9._\-]+">
  </label>
  <label class="field">
    <span>表示名</span>
    <input id="display_name" name="display_name" autocomplete="name" placeholder="Alice" required maxlength="80">
  </label>
  <label class="field">
    <span>メールアドレス <em>任意</em></span>
    <input id="email" name="email" type="email" autocomplete="email" placeholder="alice@example.com">
  </label>
  <button class="primary" id="btn-signup" type="submit">
    <span class="label">パスキーを作成</span>
  </button>
</form>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<p class="foot">すでにアカウントをお持ちの方は <a href="/login">サインイン</a></p>
{config}
</section>"#,
            brand = brand(),
            config = config
        ),
    )
}

pub fn consent_page(
    rid: &str,
    csrf: &str,
    client_name: &str,
    username: &str,
    scope: &str,
    redirect_host: &str,
) -> String {
    let scopes = split_scope(scope)
        .into_iter()
        .filter(|s| s != "openid")
        .map(|s| {
            let (title, detail) = match s.as_str() {
                "profile" => ("プロフィール", "表示名とユーザー名を共有します"),
                "email" => ("メールアドレス", "メールアドレスと確認状態を共有します"),
                "offline_access" => ("オフラインアクセス", "サインインしていない間も更新トークンでアクセスできます"),
                other => ("追加の権限", other),
            };
            format!(
                r#"<li><div class="scope-title">{}</div><div class="scope-detail">{}</div></li>"#,
                esc(title),
                esc(detail)
            )
        })
        .collect::<String>();

    let scopes = if scopes.is_empty() {
        r#"<li><div class="scope-title">サインイン</div><div class="scope-detail">あなたの識別子 (sub) のみを共有します</div></li>"#.to_string()
    } else {
        scopes
    };

    page(
        "認可",
        &format!(
            r#"<section class="card">
{brand}
<p class="eyebrow">認可リクエスト</p>
<h1>{client}</h1>
<p class="muted"><strong>{user}</strong> としてサインイン中。次の情報へのアクセスを許可します。</p>
<ul class="scopes">{scopes}</ul>
<p class="hint">リダイレクト先 <code>{host}</code></p>
<form method="post" action="/consent" class="row">
  <input type="hidden" name="rid" value="{rid}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button class="ghost" type="submit" name="decision" value="deny">拒否</button>
  <button class="primary" type="submit" name="decision" value="allow"><span class="label">許可</span></button>
</form>
</section>"#,
            brand = brand(),
            client = esc(client_name),
            user = esc(username),
            scopes = scopes,
            host = esc(redirect_host),
            rid = esc(rid),
            csrf = esc(csrf),
        ),
    )
}

pub fn account_page(user: &User, creds: &[Credential]) -> String {
    let config = config_script(&serde_json::json!({ "flow": "account" }));
    let items = if creds.is_empty() {
        r#"<li class="empty">パスキーが登録されていません</li>"#.to_string()
    } else {
        creds
            .iter()
            .map(|c| {
                let short: String = c.id.chars().take(10).collect();
                let synced = if c.backup_eligible {
                    r#"<span class="badge">同期対応</span>"#
                } else {
                    r#"<span class="badge plain">この端末のみ</span>"#
                };
                format!(
                    r#"<li class="cred"><div><div class="cred-name">{name}</div><div class="cred-id">{short}…</div></div>{synced}</li>"#,
                    name = esc(c.name.as_deref().unwrap_or("パスキー")),
                    short = esc(&short),
                    synced = synced
                )
            })
            .collect::<String>()
    };

    page(
        "アカウント",
        &format!(
            r#"<section class="card">
{brand}
<p class="eyebrow">アカウント</p>
<h1>{name}</h1>
<p class="muted">@{username}</p>
<h2>パスキー</h2>
<ul class="creds">{items}</ul>
<button class="primary" id="btn-add-passkey" type="button"><span class="label">パスキーを追加</span></button>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<form method="post" action="/account/logout" class="foot-form">
  <button class="link" type="submit">サインアウト</button>
</form>
{config}
</section>"#,
            brand = brand(),
            name = esc(&user.display_name),
            username = esc(&user.username),
            items = items,
            config = config
        ),
    )
}

/// Built-in demo relying party. Demonstrates the same browser flow an external
/// site would use through `/static/kagi.js`.
pub fn demo_page(issuer: &str, seeded: bool) -> String {
    let redirect = format!("{issuer}/demo/callback");
    let config = config_script(&serde_json::json!({
        "flow": "demo",
        "issuer": issuer,
        "client_id": "demo-web",
        "redirect_uri": redirect,
        "scope": "openid profile email",
    }));

    let notice = if seeded {
        String::new()
    } else {
        r#"<p class="hint">このデモを使うには <code>KAGI_SEED_DEMO=1</code> でサーバーを起動してください。</p>"#.to_string()
    };

    let snippet = format!(
        r#"<script src="{issuer}/static/kagi.js"></script>
<script>
  Kagi.configure({{
    issuer: "{issuer}",
    clientId: "your-client-id",
    redirectUri: location.origin + "/callback"
  }});
  Kagi.login();          // 認可エンドポイントへリダイレクト (PKCE)
  // コールバックで:
  // const session = await Kagi.handleCallback();
  // const user = await Kagi.userinfo();
</script>"#
    );

    let body = format!(
        r#"<section class="card">
{brand}
<p class="eyebrow">Demo relying party</p>
<h1>kagi でサインイン</h1>
<p class="lead">このページは、kagi を自分のサイトに組み込むときの最小構成です。ボタンは実際の認可コード + PKCE フローを実行し、ID トークンと UserInfo を表示します。</p>
{notice}
<div class="actions">
  <button class="primary" id="demo-login" type="button"><span class="label">kagi でサインイン</span></button>
  <button class="ghost" id="demo-logout" type="button" hidden>サインアウト</button>
</div>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<pre id="demo-output" hidden></pre>
<hr class="rule">
<h2>組み込み方</h2>
<p class="muted">任意のサイトに次の 2 行を置くだけです。クライアントは <code>/register</code> または管理画面から登録します。</p>
<pre><code>{snippet}</code></pre>
<p class="hint">コールバック URL はクライアント登録時の <code>redirect_uris</code> と完全一致している必要があります。</p>
{config}
</section>"#,
        brand = brand(),
        notice = notice,
        snippet = esc(&snippet),
        config = config
    );

    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>デモ · kagi</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<main class="shell">
{body}
</main>
<script src="/static/kagi.js?v=2"></script>
<script src="/static/app.js" defer></script>
</body>
</html>
"#
    )
}
