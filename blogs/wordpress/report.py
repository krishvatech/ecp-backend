"""Run report for the WordPress Blog importer: structured dict + text rendering."""
from collections import Counter

from .types import (
    ACTION_CREATE,
    ACTION_ERROR,
    ACTION_SKIP,
    ACTION_UPDATE,
    FORMATS,
    W_FAQ_SCHEMA_DETECTED,
    W_JSON_LD_REMOVED,
    W_MISSING_FEATURED_IMAGE,
)

LINK_CLASSES = ("blog", "internal", "external", "media", "anchor", "mailto", "tel", "invalid")
IMAGE_CLASSES = ("wordpress_media", "internal_site_media", "external_media", "data_url", "invalid")


def build_report(entries, *, source, category, stats, mode, selected_post_ids, duration):
    formats = Counter({f: 0 for f in FORMATS})
    actions = Counter({a: 0 for a in (ACTION_CREATE, ACTION_UPDATE, ACTION_SKIP, ACTION_ERROR)})
    warnings = Counter()
    images = Counter({c: 0 for c in IMAGE_CLASSES})
    links = Counter({c: 0 for c in LINK_CLASSES})
    embeds = Counter()
    author_ids, mapped_ids = set(), set()
    legacy_fallback_posts = 0
    featured = Counter(found=0, missing=0, unresolved=0)
    seo = Counter(missing_title=0, missing_description=0, missing_canonical=0)
    json_ld_posts = faq_posts = 0
    samples = {f: [] for f in FORMATS}
    posts, errors = [], []

    for entry in entries:
        plan, post = entry["plan"], entry["post"]
        actions[plan.action] += 1
        codes = [w.code for w in plan.warnings]
        warnings.update(set(codes))
        if plan.action == ACTION_ERROR:
            errors.append({"wp_post_id": plan.wp_post_id, "reasons": plan.reasons})
        if post is None:
            continue
        formats[post.source_format] += 1
        if plan.action != ACTION_ERROR:
            samples[post.source_format].append(post.wp_post_id)
        if post.wp_author_id:
            author_ids.add(post.wp_author_id)
            if plan.author_user_id:
                mapped_ids.add(post.wp_author_id)
        if plan.action != ACTION_ERROR and not plan.author_user_id:
            legacy_fallback_posts += 1
        if post.featured_media:
            featured["found"] += 1
        elif W_MISSING_FEATURED_IMAGE in codes:
            featured["missing"] += 1
        else:
            featured["unresolved"] += 1
        seo["missing_title"] += int(not post.seo_title)
        seo["missing_description"] += int(not post.seo_description)
        seo["missing_canonical"] += int(not post.source_canonical_url)
        json_ld_posts += int(W_JSON_LD_REMOVED in codes)
        faq_posts += int(W_FAQ_SCHEMA_DETECTED in codes)
        images.update(i.classification for i in post.content.inline_images)
        links.update(l.classification for l in post.content.internal_links)
        embeds.update(e.kind for e in post.content.embeds)
        posts.append({
            "wp_post_id": post.wp_post_id,
            "title": post.title,
            "slug": plan.slug or post.slug,
            "source_slug": post.slug,
            "format": post.source_format,
            "action": plan.action,
            "existing_post_id": plan.existing_post_id,
            "applied": entry.get("applied"),
            "published_at": post.published_at.isoformat() if post.published_at else None,
            "modified_at": post.modified_at.isoformat() if post.modified_at else None,
            "wp_author_id": post.wp_author_id,
            "author_name": post.wp_author_name,
            "ecp_author_id": plan.author_user_id,
            "categories": plan.categories,
            "tags": plan.tags,
            "featured_image": post.featured_media.url if post.featured_media else None,
            "source_url": post.source_url,
            "source_canonical_url": post.source_canonical_url,
            "seo_title": post.seo_title,
            "seo_description": bool(post.seo_description),
            "text_length": {"source": post.content.source_text_length, "normalized": post.content.text_length},
            "removed_elements": post.content.removed_elements,
            "inline_images": len(post.content.inline_images),
            "links": dict(Counter(l.classification for l in post.content.internal_links)),
            "internal_blog_links": sorted({l.blog_slug for l in post.content.internal_links if l.blog_slug}),
            "field_changes": sorted(plan.field_changes) if plan.action == ACTION_UPDATE else [],
            "taxonomy_changes": plan.taxonomy_changes,
            "warnings": [w.as_dict() for w in plan.warnings],
            "reasons": plan.reasons,
            "error": entry.get("error"),
        })

    unmapped_ids = author_ids - mapped_ids
    return {
        "mode": mode,
        "source": source,
        "category": category,
        "selected_post_ids": selected_post_ids,
        "fetch": {
            "api_total": stats.api_total,
            "api_total_pages": stats.api_total_pages,
            "pages_fetched": stats.pages_fetched,
            "posts_listed": stats.posts_fetched,
            "content_pages_fetched": stats.content_pages_fetched,
            "single_post_fallbacks": stats.single_post_fallbacks,
            "posts_processed": len(entries),
            "http_requests": stats.requests,
        },
        "formats": dict(formats),
        "plan": {
            "create": actions[ACTION_CREATE],
            "update": actions[ACTION_UPDATE],
            "skip": actions[ACTION_SKIP],
            "error": actions[ACTION_ERROR],
        },
        "authors": {
            "unique_wp_authors": len(author_ids),
            "mapped": len(mapped_ids),
            "unmapped": len(unmapped_ids),
            "unmapped_ids": sorted(unmapped_ids),
            "posts_using_legacy_author": legacy_fallback_posts,
        },
        "featured_media": dict(featured),
        "content": {
            "inline_images": sum(images.values()),
            "inline_images_by_class": dict(images),
            "links_by_class": dict(links),
            "embeds": dict(embeds),
            "posts_with_json_ld": json_ld_posts,
            "posts_with_faq_schema": faq_posts,
        },
        "seo": dict(seo),
        "warnings": dict(warnings.most_common()),
        "sample_candidates": {f: ids[:5] for f, ids in samples.items()},
        "errors": errors,
        "posts": posts,
        "duration_seconds": round(duration, 2),
    }


def render_text(report):
    line = "=" * 50
    sub = "-" * 38
    out = [line, f"WordPress Blog Import {'Dry Run' if report['mode'] == 'dry-run' else 'Commit'}", line, ""]
    cat = report["category"]
    fetch = report["fetch"]
    out += [
        f"Source:      {report['source']}",
        f"Category:    {cat['id']} - {cat['name']} (slug '{cat['slug']}', WordPress count {cat.get('count')})",
        f"REST total:  {fetch['api_total']}",
        f"Listing pages: {fetch['pages_fetched']} (of {fetch['api_total_pages']})   posts listed: {fetch['posts_listed']}",
        f"Content pages: {fetch['content_pages_fetched']}   single-post fallbacks: {fetch['single_post_fallbacks']}",
        f"Posts processed: {fetch['posts_processed']}   HTTP requests: {fetch['http_requests']}",
    ]
    if report["selected_post_ids"]:
        out.append(f"Selected post IDs: {', '.join(str(i) for i in report['selected_post_ids'])}")

    def section(title, rows):
        out.extend(["", sub, title, sub])
        out.extend(f"{label}: {value}" for label, value in rows)

    section("CONTENT FORMATS", [(f.capitalize(), n) for f, n in report["formats"].items()])
    verb = "Would " if report["mode"] == "dry-run" else ""
    plan = report["plan"]
    section("IMPORT PLAN", [(f"{verb}create", plan["create"]), (f"{verb}update", plan["update"]),
                            (f"{verb}skip", plan["skip"]), ("Errors", plan["error"])])
    authors = report["authors"]
    section("AUTHORS", [("Unique WP authors", authors["unique_wp_authors"]), ("Mapped to ECP users", authors["mapped"]),
                        ("Unmapped", f"{authors['unmapped']} {authors['unmapped_ids']}"),
                        ("Posts using legacy author name", authors["posts_using_legacy_author"])])
    fm = report["featured_media"]
    section("FEATURED MEDIA (not migrated in Batch 3)", [("Found", fm["found"]), ("Missing", fm["missing"]),
                                                         ("Unresolved", fm["unresolved"])])
    content = report["content"]
    links = content["links_by_class"]
    section("CONTENT", [
        ("Inline images", f"{content['inline_images']} {content['inline_images_by_class']}"),
        ("Internal Blog links", links.get("blog", 0)),
        ("Other IMAA links", links.get("internal", 0)),
        ("IMAA media/download links", links.get("media", 0)),
        ("External links", links.get("external", 0)),
        ("Anchor/mailto/tel/invalid", f"{links.get('anchor', 0)}/{links.get('mailto', 0)}/{links.get('tel', 0)}/{links.get('invalid', 0)}"),
        ("Embeds", content["embeds"] or 0),
        ("Posts with JSON-LD / FAQ schema", f"{content['posts_with_json_ld']} / {content['posts_with_faq_schema']}"),
    ])
    seo = report["seo"]
    section("SEO", [("Missing SEO title", seo["missing_title"]), ("Missing SEO description", seo["missing_description"]),
                    ("Missing canonical", seo["missing_canonical"])])
    section("WARNINGS (posts affected per code)", list(report["warnings"].items()) or [("None", "")])
    section("SAMPLE CANDIDATES BY FORMAT", [(f, ids) for f, ids in report["sample_candidates"].items() if ids])
    if report["errors"]:
        section("ERRORS", [(e["wp_post_id"], "; ".join(e["reasons"])) for e in report["errors"]])
    if report["mode"] == "commit":
        section("APPLIED", [
            (p["wp_post_id"], f"{p['action']} -> BlogPost {(p['applied'] or {}).get('blog_post_id') or p['existing_post_id'] or '-'} "
                              f"slug '{p['slug']}'")
            for p in report["posts"]
        ])
    out += ["", line, f"Finished in {report['duration_seconds']}s", line]
    return "\n".join(out)
