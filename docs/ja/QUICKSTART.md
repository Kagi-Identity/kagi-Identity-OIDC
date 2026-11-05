# クイックスタート

このガイドでは、デモ用の RP（Relying Party）を含む Kagi Identity のローカル環境を最短で立ち上げます。開発・評価専用の手順であり、本番環境の構築手順ではありません。

## 必要なもの

- Docker Engine / Docker Desktop と Compose プラグイン（方法 A）
- または Rust の安定版ツールチェーン（`Cargo.toml` に記載の最小バージョン以上）と Cargo（方法 B）
- パスキーを作成できるブラウザーと OS（Windows Hello、Touch ID、Android / iOS の生体認証、セキュリティキーなど）

## 方法 A: Docker Compose（推奨）

リポジトリのルートで次を実行します。

```bash
docker compose up --build -d
docker compose logs -f kagi
```

起動後に次の URL を開きます。

| 用途 | URL |
| --- | --- |
| Identity ホーム / アカウントコンソール | http://localhost:8080/ |
| パスキーアカウント作成 | http://localhost:8080/signup |
| 組み込み RP デモ | http://localhost:8080/demo |
| OIDC Discovery | http://localhost:8080/.well-known/openid-configuration |
| 公開署名鍵（JWKS） | http://localhost:8080/jwks.json |

1. `/signup` を開き、端末の画面ロック・生体認証・セキュリティキーを使ってパスキーを作成します。
2. `/` のアカウントコンソールでプロフィール、パスキー、端末、連携アプリを確認します。
3. `/demo` を開いてサインインし、認可コードフローがコールバックまで完了することを確認します。

ローカルの SQLite データベースと署名鍵は `kagi-data` という Docker ボリュームに保存されます。

停止するには:

```bash
docker compose down
```

データベースと署名鍵も**完全に削除**する場合は次を実行します。この操作は元に戻せません。

```bash
docker compose down --volumes
```

### ローカル Compose の設定

Compose の既定値はローカル評価専用です。HTTP、ループバックへのポート公開、デモクライアントの自動登録、誰でもサインアップ可能な設定になっています。**このままインターネットへ公開しないでください。**

設定を変更する場合は `.env.example` をコピーして編集します。

```bash
cp .env.example .env
```

`.env` は秘密情報を含みうるため、絶対にコミットしないでください。

## 方法 B: Rust で直接実行する

```bash
cp .env.example .env
# ローカル開発用の既定値です。別の環境で使う前に必ず見直してください。
set -a
. ./.env
set +a
cargo run --locked
```

ブラウザーで http://localhost:8080 を開きます。

PowerShell では POSIX の `.env` を source する代わりに、現在のターミナルで環境変数を設定します。

```powershell
$env:KAGI_ISSUER = "http://localhost:8080"
$env:KAGI_RP_ID = "localhost"
$env:KAGI_ORIGIN = "http://localhost:8080"
$env:KAGI_SEED_DEMO = "1"
cargo run --locked
```

## 動作確認

```bash
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/readyz
curl --fail http://localhost:8080/.well-known/openid-configuration
curl --fail http://localhost:8080/jwks.json
```

- `/healthz` はプロセスの稼働確認です。
- `/readyz` はデータベースと署名鍵テーブルまで確認します。スキーマが半適用の状態を「正常」と報告しないため、デプロイ時はこちらを使ってください。
- Discovery の `issuer` は、ブラウザーからアクセスする URL と完全に一致している必要があります。`localhost` と `127.0.0.1` は別のオリジンです。

## 初回サインインとアカウントコンソール

1. `/signup` でユーザー名・表示名を入力し、パスキーを作成します。
2. 作成直後にセッションが発行され、`/` のアカウントコンソールへ移動します。
3. プロフィール（表示名・メールアドレス）を編集できます。変更は UserInfo に即時反映されます。
4. 「パスキー」から追加・名前変更・削除ができます。最後の 1 個は削除できません（ロックアウト防止）。
5. 「サインイン中のデバイス」でセッションを確認し、個別または一括でサインアウトできます。失効はそのセッションから発行されたアクセストークンとリフレッシュトークンにも及びます。
6. 「連携アプリ」で同意済みクライアントを確認し、同意を取り消せます。取消時はそのクライアントのトークンも失効します。
7. 「リカバリーコード」で単回使用コードを生成できます。詳細は [アカウント管理](ACCOUNT.md) を参照してください。

## よくある問題

| 症状 | 確認すること |
| --- | --- |
| パスキー作成に失敗する | ブラウザーで `localhost` を使っているか。WebAuthn は secure context が必要で、LAN の IP への HTTP は localhost と同等ではありません。 |
| issuer / origin の不一致 | `KAGI_ISSUER` と `KAGI_ORIGIN` をブラウザーから見える正確なオリジン（末尾スラッシュなし）に設定します。`KAGI_RP_ID` はスキームもポートも含めないホスト名だけです。 |
| ポート 8080 が使用中 | Compose のポートマッピングと、関連する issuer / origin の値をまとめて変更します。1 つだけ変えないでください。 |
| デモページでクライアントが見つからない | Compose は既定でデモクライアントを登録します。手動実行の場合は初回起動前に `KAGI_SEED_DEMO=1` を設定します。 |
| データベースを初期化したい | サービスを停止し、必要なデータをバックアップします。Compose では `docker compose down --volumes` でテスト用ボリュームと全データが削除されます。 |
| 再デプロイ後にログインできない | SQLite ファイルや署名鍵が永続化されているか、複数インスタンスで共有されているかを確認します。本番では PostgreSQL を使用してください。 |

## ローカル開発の先へ

本番相当の構成へ進む前に、[デプロイガイド](DEPLOYMENT.md)、[設定リファレンス](CONFIGURATION.md)、[セキュリティポリシー](SECURITY.md) を必ず読んでください。デモ用の認証情報、HTTP 設定、開発用データベースを本番へ流用しないでください。
