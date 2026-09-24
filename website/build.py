"""Build the static threatveil.com site into website/public.

    uv run --no-project --with markdown==3.8.2 python website/build.py

Articles are rendered from docs/blog/*.md, so the repository and the site share one source.
The output is committed; CI rebuilds it and fails if website/public drifts.
"""

import html
import json
import re
import shutil
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "website"
SRC = SITE / "src"
OUT = SITE / "public"
BASE_URL = "https://threatveil.com"
REPO = "https://github.com/sandrexa1111/threatveil-oss"
# Fixed so that a rebuild without content changes produces identical files.
SITE_UPDATED = "2026-09-14"
DOC_IMAGES = ["assurance-lifecycle.svg", "architecture.svg", "system-cleared.png",
              "change-impact.png", "proposed-change.png", "passport-share.png", "demo.gif"]


def front_matter(text):
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not match:
        raise ValueError("Article is missing front matter")
    meta = dict(line.split(": ", 1) for line in match.group(1).splitlines())
    return meta, text[match.end():]


def repo_links(rendered, source_dir):
    """Relative links in docs point into the repository; send them to GitHub."""

    def rewrite(match):
        href = match.group(1)
        if re.match(r"^(https?:|mailto:|#|/)", href):
            return match.group(0)
        path, _, anchor = href.partition("#")
        target = (source_dir / path).resolve().relative_to(ROOT).as_posix()
        kind = "tree" if (ROOT / target).is_dir() else "blob"
        return f'href="{REPO}/{kind}/main/{target}{"#" + anchor if anchor else ""}"'

    return re.sub(r'href="([^"]+)"', rewrite, rendered)


def render(template, *, title, description, path, body, og_type="website", jsonld=None,
           robots="index,follow"):
    values = {
        "title": html.escape(title),
        "description": html.escape(description),
        "canonical": BASE_URL + path,
        "og_type": og_type,
        "robots": robots,
        "jsonld": json.dumps(jsonld, indent=2) if jsonld else "{}",
        "body": body,
    }
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values[m.group(1)], template)


def write(path, content):
    target = OUT / path.lstrip("/")
    if path.endswith("/"):
        target = target / "index.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def main():
    template = (SRC / "base.html").read_text()
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(SRC / "static", OUT)
    (OUT / "images").mkdir(exist_ok=True)
    for name in DOC_IMAGES:
        shutil.copy2(ROOT / "docs" / "images" / name, OUT / "images" / name)

    software = {
        "@context": "https://schema.org", "@type": "SoftwareSourceCode",
        "name": "ThreatVeil", "url": BASE_URL, "codeRepository": REPO,
        "license": "https://www.apache.org/licenses/LICENSE-2.0",
        "programmingLanguage": ["Python", "TypeScript"],
        "description": "Open-source assurance infrastructure for tracking whether security "
                       "evidence still applies as autonomous AI systems change.",
    }
    pages = [
        ("/", "index.html", "ThreatVeil · Open-source assurance for changing AI systems",
         "Know which security conclusions still hold after your AI system changes. ThreatVeil "
         "tracks how changes to tools, permissions, models and configuration affect the security "
         "evidence behind autonomous AI systems.", software),
        ("/status/", "status.html", "Project status · ThreatVeil",
         "ThreatVeil began as a commercial startup experiment and is now an open-source research "
         "and engineering project. What works, what is experimental, and how to contribute.", None),
    ]
    urls = []
    for path, source, title, description, jsonld in pages:
        write(path, render(template, title=title, description=description, path=path,
                           body=(SRC / source).read_text(), jsonld=jsonld))
        urls.append((path, SITE_UPDATED))

    articles = []
    for source in sorted((ROOT / "docs" / "blog").glob("*.md")):
        meta, text = front_matter(source.read_text())
        text = re.sub(r"^# .*\n", "", text.lstrip("\n"), count=1)
        rendered = markdown.markdown(text, extensions=["fenced_code", "tables"])
        rendered = repo_links(rendered, source.parent)
        path = f"/blog/{meta['slug']}/"
        body = (f'<article class="article wrap narrow"><p class="eyebrow"><a href="/blog/">Blog</a>'
                f' · <time datetime="{meta["date"]}">{meta["date"]}</time></p>'
                f'<h1>{html.escape(meta["title"])}</h1>'
                f'<p class="lede">{html.escape(meta["description"])}</p>'
                f'<div class="prose">{rendered}</div>'
                f'<p class="article-foot"><a href="{REPO}/blob/main/docs/blog/{source.name}">'
                f'Source on GitHub</a> · <a href="{REPO}">ThreatVeil repository</a></p></article>')
        posting = {"@context": "https://schema.org", "@type": "BlogPosting",
                   "headline": meta["title"], "description": meta["description"],
                   "datePublished": meta["date"], "mainEntityOfPage": BASE_URL + path,
                   "author": {"@type": "Organization", "name": "ThreatVeil maintainers"},
                   "image": BASE_URL + "/og.png"}
        write(path, render(template, title=f'{meta["title"]} · ThreatVeil',
                           description=meta["description"], path=path, body=body,
                           og_type="article", jsonld=posting))
        articles.append((meta, path))
        urls.append((path, meta["date"]))

    items = "".join(
        f'<li><a href="{path}"><span class="post-title">{html.escape(m["title"])}</span>'
        f'<span class="post-desc">{html.escape(m["description"])}</span>'
        f'<time datetime="{m["date"]}">{m["date"]}</time></a></li>'
        for m, path in sorted(articles, key=lambda a: a[0]["date"], reverse=True))
    body = (f'<section class="wrap narrow article"><p class="eyebrow">Blog</p><h1>Writing</h1>'
            f'<p class="lede">Essays on evidence applicability, autonomous-system assurance and '
            f'what we learned building ThreatVeil.</p><ul class="posts">{items}</ul></section>')
    write("/blog/", render(template, title="Blog · ThreatVeil", path="/blog/", body=body,
                           description="Essays on security evidence, evidence invalidation and "
                                       "assurance for changing autonomous AI systems."))
    urls.append(("/blog/", SITE_UPDATED))

    write("/404.html", render(template, title="Not found · ThreatVeil", path="/404.html",
                              description="This page does not exist.", robots="noindex",
                              body=(SRC / "404.html").read_text()))

    sitemap = "".join(f"<url><loc>{BASE_URL}{p}</loc><lastmod>{d}</lastmod></url>" for p, d in urls)
    (OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{sitemap}</urlset>\n')
    print(f"Built {len(urls) + 1} pages into {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
