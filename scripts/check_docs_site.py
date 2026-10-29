#!/usr/bin/env python3
"""Validate the static Kagi Identity documentation site without third-party packages."""
from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import sys


SITE = Path("examples/identity-docs/index.html")
REQUIRED_IDS = {
    "top",
    "overview",
    "quickstart",
    "first-login",
    "oidc",
    "client",
    "web",
    "architecture",
    "deployment",
    "database",
    "security",
    "testing",
    "troubleshooting",
    "status",
}
REQUIRED_LINKS = {
    "https://github.com/akiy2009/kagi",
    "https://kagi-rp-demo-gakusei-bot.vercel.app",
}


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.fragments: list[str] = []
        self.external_blank_links: list[tuple[str, str]] = []
        self.links: set[str] = set()
        self.html_lang: str | None = None
        self.title_seen = False
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "html":
            self.html_lang = attrs_dict.get("lang")
        if tag == "title":
            self._in_title = True
        element_id = attrs_dict.get("id")
        if element_id:
            self.ids.append(element_id)
        if tag == "a":
            href = attrs_dict.get("href") or ""
            if href.startswith("#") and len(href) > 1:
                self.fragments.append(href[1:])
            if href.startswith(("https://", "http://")):
                self.links.add(href)
                if attrs_dict.get("target") == "_blank":
                    self.external_blank_links.append((href, attrs_dict.get("rel") or ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title_seen = True


def main() -> int:
    if not SITE.is_file():
        print(f"ERROR: documentation site not found: {SITE}", file=sys.stderr)
        return 1

    parser = SiteParser()
    parser.feed(SITE.read_text(encoding="utf-8"))
    parser.close()

    errors: list[str] = []
    duplicate_ids = sorted(key for key, count in Counter(parser.ids).items() if count > 1)
    if duplicate_ids:
        errors.append("duplicate HTML ids: " + ", ".join(duplicate_ids))

    missing_ids = sorted(REQUIRED_IDS - set(parser.ids))
    if missing_ids:
        errors.append("required section ids missing: " + ", ".join(missing_ids))

    broken_fragments = sorted(set(parser.fragments) - set(parser.ids))
    if broken_fragments:
        errors.append("broken in-page links: " + ", ".join("#" + value for value in broken_fragments))

    if parser.html_lang != "ja":
        errors.append(f'expected <html lang="ja">, got {parser.html_lang!r}')
    if not parser.title_seen:
        errors.append("page title is missing")

    missing_links = sorted(REQUIRED_LINKS - parser.links)
    if missing_links:
        errors.append("required links missing: " + ", ".join(missing_links))

    unsafe_blank_links = [
        href for href, rel in parser.external_blank_links
        if not {"noopener", "noreferrer"}.issubset(set(rel.lower().split()))
    ]
    if unsafe_blank_links:
        errors.append("external target=_blank links must use rel=noopener noreferrer: " + ", ".join(unsafe_blank_links))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "Documentation site checks passed: "
        f"{len(parser.ids)} ids, {len(parser.fragments)} in-page links, "
        f"{len(parser.links)} external links."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
