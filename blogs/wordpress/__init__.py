"""
WordPress Blog import foundation (read-only source: the public IMAA REST API).

Pipeline, each stage in its own module and free of DB writes except `importer`:

    client      -> fetch category/posts/taxonomy/media (requests, timeouts, pagination)
    parser      -> raw WordPress JSON -> NormalizedWordPressBlog (parsed once)
    formats     -> gutenberg / elementor / classic / mixed / unknown detection
    normalizer  -> WordPress HTML -> sanitised semantic HTML (bs4 structure + nh3)
    planner     -> CREATE / UPDATE / SKIP / ERROR plan against the ECP database
    importer    -> runs the pipeline; dry-run (no writes) or per-post atomic commit
    report      -> run summary (text + JSON)
"""
