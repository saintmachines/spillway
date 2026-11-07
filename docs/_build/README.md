# Building the project page

The page is served from `main:/docs` at `/spillway/`.

Run the checks with Python 3.12 or newer and the dev and AgentDojo extras:

```bash
PYTHONPATH=src python docs/_build/capture_checks.py
PYTHONPATH=src python docs/_build/build_page.py
```

`publication.json` contains publication facts used for the install controls.
While `pypi_version` is `null`, the page selects the source command and disables
the pip and uv registry tabs. After the exact version is published and a fresh
installation from PyPI has passed, set `pypi_version` to that version and rebuild.
The builder reads this file offline and accepts only the current project version.
`source_ref` must name an existing tag or commit before the page is published.

The paper link uses `docs/SPILLWAY_preprint.pdf`. Keep that file identical to the
released preprint. Bibliographic URLs can use that PDF before a real arXiv
identifier is assigned.

The GitHub README uses relative pictures so they also load in the private
repository. Regenerate those pictures after the final page build:

```bash
PLAYWRIGHT_CORE=/path/to/playwright-core/index.mjs node docs/_build/make_readme_media.mjs
```

Its manifest pins the input page and each picture. `PYPI_README.md` is the
distribution's plain Markdown description, with absolute image URLs and the
registry install command. Upload the distribution only after the public links
work. After uploading, verify a fresh registry install before enabling the
registry tabs in `publication.json`.

The social cards have an HTML source in `og.html`. `assets/og-card.png`, 1200 by
630 pixels, is the page's share image. `assets/social-card-1280x640.png` is the
repository's social preview, which GitHub takes only as an upload in the
repository settings. With the docs directory served locally, regenerate both:

```bash
PLAYWRIGHT_CORE=/path/to/playwright-core/index.mjs node docs/_build/make_og_card.mjs http://127.0.0.1:8000/
```

`build_page.py` also writes `integrate.html`. The results and integration pages
take the product header, with its maker link, and the footer from the rendered
home page.
`try/make_try.py` composes `docs/try.html` from the built `integrate.html` and copies the released wheel to `docs/assets/try/`. Run it after a page build, with the wheel's path as its second argument.
Keep the current `try.html` unchanged during page-only builds while it embeds the 0.1.0 wheel. Rebuilding it from the 0.1.1 integration page would replace its version link and footer without changing the wheel.
Their small navigation helper is `assets/subpage.js`. Keep these shared routes
and the current page marker covered when adding a page.

The runnable app examples under `docs/examples/` are checkout documentation.
They exercise the 0.1.1 API and are excluded from the wheel and source
distribution together with the rest of `docs/`.
