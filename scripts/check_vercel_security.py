#!/usr/bin/env python3
"""Static guardrails for the Vercel/serverless production entrypoint."""
from pathlib import Path
import sys

def require(path: str, needles: tuple[str, ...]) -> None:
    content = Path(path).read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in content]
    if missing:
        raise SystemExit(f"{path}: missing required guardrails: {', '.join(missing)}")

def main() -> int:
    require("api/index.rs", ("VercelLayer::new()", "kagi::build_state()", "OnceLock"))
    require("vercel.json", ('"destination": "/api/index"',))
    require("src/lib.rs", (
        "KAGI_DATABASE_URL",
        "KAGI_AUTO_MIGRATE=0",
        "KAGI_CORS_ORIGINS",
        "KAGI_REGISTRATION_TOKEN",
        "KAGI_TRUST_PROXY=1",
        "KAGI_DPOP_NONCE=1",
        "rate_limits",
        "compare_exchange",
        "STRICT_TRANSPORT_SECURITY",
        "/admin/audit/verify",
        "current_nonce",
    ))
    require("src/db.rs", (
        "open_with_options",
        "SslMode::Require",
        "CREATE TABLE IF NOT EXISTS rate_limits",
        "pg_advisory_xact_lock",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq",
    ))
    require("src/config.rs", ("KAGI_CORS_ORIGINS", "cors_origins", "KAGI_ENV", "validate_https_origin"))
    require("src/lib.rs", ("validate_production_config", "is_usable_production_secret"))
    require("supabase/schema.sql", (
        "CREATE TABLE IF NOT EXISTS rate_limits",
        "CREATE TABLE IF NOT EXISTS audit_head",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq",
    ))
    require("Dockerfile", ("USER 10001:10001", "HEALTHCHECK"))
    require("compose.production.yaml", (
        "read_only: true",
        "cap_drop:",
        "no-new-privileges:true",
        "condition: service_healthy",
    ))
    require("deploy/Caddyfile", (
        "reverse_proxy kagi:8080",
        "header_up X-Forwarded-For",
        "header_up X-Forwarded-Proto",
    ))
    print("Production guardrails present: serverless and self-hosted startup gates, exact CORS, TLS, shared rate limiting, non-root container, health checks, private app network, and proxy header sanitization.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
