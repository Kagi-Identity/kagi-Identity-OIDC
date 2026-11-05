# デプロイガイド

このガイドは運用者向けのチェックリストです。Kagi Identity はセキュリティに敏感なリファレンス実装であり、OAuth / OpenID Connect / FAPI の適合認証を受けた製品ではありません。ビルドの成功は、脅威モデリング、独立したレビュー、プロファイル別の適合テストの代わりにはなりません。

## 1. 本番アーキテクチャ

典型的な構成は次のとおりです。

1. 公開 HTTPS リバースプロキシ / ロードバランサー
2. プライベートインターフェースまたはプライベートコンテナネットワークにバインドした Kagi Identity
3. 永続データベースと保護されたバックアップ
4. 集中管理された秘密情報ストレージと監視

TLS はメンテナンスされたリバースプロキシで終端します。プロキシはクライアントが送った forwarded ヘッダーを受けそのまま使うのではなく、**上書き**するように設定してください。`KAGI_TRUST_PROXY=1` は、サービスが信頼済みプロキシ経由でのみ到達可能で、そのプロキシが `X-Forwarded-For` を上書きする場合に限り有効にします。

Kagi のポートをインターネットへ直接公開しないでください。エッジでリクエスト / ボディサイズ制限とタイムアウトを設定します。アプリケーション側も PostgreSQL の原子的カウンタでレート制限を行うため、独立にスケールしたインスタンス間で制限が共有されます。

## 2. セルフホスト Docker デプロイ

リポジトリには、Docker Engine と Compose を持つ Linux ホスト向けの本番 Compose テンプレートが含まれています。Kagi は非 root・読み取り専用コンテナとして動作し、Caddy が HTTPS 証明書を自動取得・更新します。PostgreSQL は意図的に外部化されています。TLS、バックアップ、監視、制限されたネットワークアクセスを持つマネージド PostgreSQL、または別途運用するデータベースを使用してください。

1. Identity のホスト名（例: `identity.example.com`）を Docker ホストへ向けます。受信 TCP 80 / 443 を許可します。HTTP/3 を使う場合は UDP 443 も許可します。
2. データベースと最小権限のアカウントを作成します。ホストから到達可能な TLS 有効の PostgreSQL URL を `KAGI_DATABASE_URL` に設定します。
3. Kagi 起動前にスキーマを一度だけ適用します。

   ```bash
   read -r -s -p "PostgreSQL TLS URL: " KAGI_DATABASE_URL
   echo
   export KAGI_DATABASE_URL
   psql "$KAGI_DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/schema.sql
   unset KAGI_DATABASE_URL
   ```

   URL は秘密管理領域または保護されたシェル環境で扱い、シェル履歴に残るコマンドリテラルへ直接書かないでください。
4. `.env.production.example` を `.env.production` にコピーします。ドメイン、メールアドレス、データベース URL、RP のオリジン、2 つのランダム秘密値を置き換えます。秘密値は `openssl rand -base64 48` などで個別に生成します。`.env.production` はバージョン管理に含めないでください。
5. レンダリングされた設定を確認して起動します。

   ```bash
   docker compose --env-file .env.production -f compose.production.yaml config --quiet
   docker compose --env-file .env.production -f compose.production.yaml up --build -d
   docker compose --env-file .env.production -f compose.production.yaml ps
   docker compose --env-file .env.production -f compose.production.yaml logs -f kagi caddy
   ```
6. HTTPS エンドポイントを確認します。

   ```bash
   curl --fail https://identity.example.com/healthz
   curl --fail https://identity.example.com/readyz
   curl --fail https://identity.example.com/.well-known/openid-configuration
   curl --fail https://identity.example.com/jwks.json
   ```

   Discovery の `issuer` は `KAGI_ISSUER` と完全一致している必要があります。

本番スタックはホスト上に Caddy のみを公開します。Kagi はプライベート Compose ネットワーク上で UID 10001 として動作し、Linux ケーパビリティを落とし、読み取り専用ルートファイルシステムを使い、データベース検査付きの readiness を持ちます。Caddy は Kagi の信頼済みプロキシ用レート制限が使う forwarded ヘッダーを上書きします。

更新する際は、対象リビジョンを取得・レビューし、PostgreSQL と Caddy データボリュームをバックアップしたうえで、同じ Compose コマンドで再ビルドします。将来のスキーマ変更は、アプリケーションのロールアウト前に管理された単発操作として適用してください。本番の同時起動中に自動マイグレーションを有効にしないでください。

この例が外部 PostgreSQL を使うのは意図的です。データベースのインストール、保護、バックアップ、監視までは行いません。コンテナが起動しただけでは、運用上安全な Identity サービスの証明になりません。データベースのバックアップとリストア演習、秘密のローテーション、アラート、レート / 接続制限、インシデント対応プロセスを構成してください。

## 3. 必須の Identity 設定

公開オリジンを 1 つ決め、一貫して使います。以下はプレースホルダーです。

```dotenv
KAGI_ENV=production
KAGI_ISSUER=https://id.example.com
KAGI_ORIGIN=https://id.example.com
KAGI_RP_ID=example.com
KAGI_RP_NAME=Example Identity
KAGI_BIND=127.0.0.1:8080
KAGI_COOKIE_SECURE=1
KAGI_HSTS=1
KAGI_SEED_DEMO=0
KAGI_ALLOW_SIGNUP=0
KAGI_REQUIRE_PAR=1
KAGI_REQUIRE_DPOP=1
KAGI_RATE_LIMIT=1
KAGI_TRUST_PROXY=1
KAGI_CORS_ORIGINS=https://your-rp.example.com
```

すべて実際のデプロイ値に置き換えてください。`KAGI_ISSUER` と `KAGI_ORIGIN` はオリジンであり、パス、クエリ、フラグメント、末尾スラッシュを含む URL ではありません。`KAGI_RP_ID` はスキームもポートも含まないホスト / ドメインだけです。RP ID とブラウザーオリジンが不整合だとパスキーは失敗します。

`KAGI_REQUIRE_PAR=1` と `KAGI_REQUIRE_DPOP=1` は厳格なリクエスト処理を有効にしますが、FAPI 2.0 準拠を証明するものではありません。有効化する前に、各 RP が対応するフローを検証してください。

## 4. OCI 互換コンテナプラットフォーム

同じ `Dockerfile` から移植可能な OCI イメージをビルドできます。CI または信頼できるビルドホストでビルドし、プライベートコンテナレジストリへ公開して、コンテナを実行できるプラットフォームへデプロイします。プラットフォームの ingress で HTTPS を終端し、コンテナポート `8080` へ転送します。Kagi コンテナをインターネットへ直接公開しないでください。

[設定リファレンス](CONFIGURATION.md) に記載された本番変数を設定します。`KAGI_ENV=production`、`KAGI_BIND=0.0.0.0:8080`、TLS 有効の PostgreSQL URL、正確な issuer / origin / RP ID、異なる強力な管理・登録トークンを含みます。初回ロールアウト前に `supabase/schema.sql` を単発マイグレーションとして適用します。Readiness probe には `GET /healthz` を設定します。このエンドポイントはプロセスの生存だけでなく、データベースと署名鍵テーブルを確認します。

`KAGI_TRUST_PROXY=1` は、プラットフォームの信頼済み ingress が `X-Forwarded-For` を上書きする場合に限り設定します。そうでない場合は Kagi をプライベートに保ち、forwarded ヘッダーを sanitize するプロキシを前段に置いてから有効にしてください。アプリケーションポートをプライベートに保ち、外部データベースを永続化し、バックアップ / リストア、秘密ローテーション、監視、ローリングデプロイの挙動をプラットフォーム側で構成します。

## 5. Vercel Rust Runtime

Vercel では `api/index.rs` の Axum アダプターを使う公式 Rust Runtime を利用します。すべての HTTP パスは同じ Axum ルーターへ rewrite されます。ローカルの `TcpListener` サーバーを Vercel Function として実行しないでください。

Vercel 本番では、PostgreSQL、HTTPS で同一の issuer / WebAuthn origin、Secure Cookie と HSTS、デモ無効、PAR 必須、信頼済みプロキシ、正確な HTTPS CORS 許可リスト、強力な管理 / 登録トークンが揃わない限り起動に失敗します。値は Vercel Project Settings → Environment Variables に設定し、実際の資格情報をコミットしないでください。

Vercel 設定例:

```dotenv
KAGI_ISSUER=https://your-identity-domain.example
KAGI_ORIGIN=https://your-identity-domain.example
KAGI_RP_ID=your-identity-domain.example
KAGI_DATABASE_URL=<TLS-enabled PostgreSQL pooler URL>
KAGI_AUTO_MIGRATE=0
KAGI_COOKIE_SECURE=1
KAGI_HSTS=1
KAGI_SEED_DEMO=0
KAGI_REQUIRE_PAR=1
KAGI_TRUST_PROXY=1
KAGI_RATE_LIMIT=1
KAGI_CORS_ORIGINS=https://your-rp.example.com
KAGI_ADMIN_TOKEN=<32 文字以上のランダム秘密値>
KAGI_REGISTRATION_TOKEN=<別の 32 文字以上のランダム秘密値>
```

デプロイ前に `supabase/schema.sql` をデータベースのマイグレーション手順で一度だけ適用し、`KAGI_AUTO_MIGRATE=0` にします。複数のサーバーレスインスタンスが同時にコールドスタートする際の DDL 競合を避けるためです。現在、各ウォームインスタンスは 1 本の直列化されたデータベース接続を保持します。サーバーレスの接続数制限にはマネージド PostgreSQL プーラーを使い、本番トラフィック前に負荷試験を行ってください。

## 6. 秘密情報

高エントロピーの値をソース管理外で生成します。OpenSSL がある環境では:

```bash
openssl rand -base64 48
```

`KAGI_ADMIN_TOKEN` と `KAGI_REGISTRATION_TOKEN` には別々の値を使います。秘密管理領域に保存し、アクセスを制限し、漏洩が疑われる場合はローテーションし、Issue、チャットログ、ソースコードへ貼り付けないでください。

- `KAGI_ADMIN_TOKEN` は管理用の鍵ローテーションを保護します。
- `KAGI_REGISTRATION_TOKEN` は動的クライアント登録を制限します。
- 既知の値や短いプレースホルダーでこれらのエンドポイントを有効にしないでください。
- 秘密情報をログ、クラッシュレポート、CI 出力、可能な限りシェル履歴に残さないでください。

## 7. ストレージと鍵の保護

SQLite はローカル開発と単一ノードデプロイに便利です。PostgreSQL / Supabase では、プライベートで TLS 有効の接続文字列を `KAGI_DATABASE_URL` に設定します。データベースを公開クライアントから到達不能にし、可能な場合は最小権限の DB アカウントを使ってください。

この実装では署名鍵をデータベースに永続化します。そのため**データベースのバックアップには機密の鍵素材が含まれます**。バックアップを暗号化し、リストア権限を制限し、復元を演習し、保持期間を定めてください。高保証の本番利用前には、外部 KMS / HSM による鍵管理を検討してください。

PostgreSQL はセッション、認可コード、フロー、リフレッシュ / アクセストークン状態、署名鍵、DPoP リプレイ記録、共有レート制限カウンタを保存します。各インスタンスは署名鍵リングを短時間キャッシュし、ローテーション後に収束するよう 5 秒ごとに更新します。データベース接続自体は各ウォームインスタンス内で直列化されます。プーラーを使い、負荷試験を行ってください。複数インスタンス対応ではありますが、無制限の水平スケールやゼロダウンタイムフェイルオーバーを主張するものではありません。

## 8. 推奨ロールアウト

1. 公開オリジン、RP ID、TLS、秘密管理を設定する。
2. デモ登録を無効にし、セルフサインアップの可否を決める。
3. 正確な redirect URI を持つテストクライアントを 1 つ登録する。
4. 分離環境でユニットテストと統合テストを実行する。
5. プロファイル別の OAuth / OIDC 適合テストと独立したセキュリティレビューを実施する。
6. バックアップ復元、署名鍵ローテーション、インシデント対応、ログの秘匿化を検証する。
7. 認証失敗、レート制限、データベース健全性、鍵ローテーションを監視する。
8. 一般公開前に少数のテストクライアントへ段階的に展開する。

## 9. 公開前チェックリスト

- [ ] HTTPS がエンドツーエンドで強制され、HTTP リダイレクトとプロキシ挙動を確認した。
- [ ] Issuer、WebAuthn Origin、RP ID が整合している。
- [ ] `KAGI_SEED_DEMO=0` で、サインアップポリシーを意図的に決めた。
- [ ] 管理トークンと登録トークンが強力・非公開・別管理である。
- [ ] レート制限とボディサイズ制限を信頼済みエッジで実施している。
- [ ] データベースアクセス、バックアップ、リストア試験、鍵素材を保護している。
- [ ] ログに認可コード、アクセス / リフレッシュトークン、セッション ID、資格情報素材が含まれない。
- [ ] 対象プロファイルの OAuth / OIDC / FAPI 適合テストと独立セキュリティレビューを完了した。
- [ ] ロールバックとインシデント対応手順を演習した。
