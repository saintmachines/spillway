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

The paper link uses the reviewed `docs/SPILLWAY_preprint.pdf`. Keep that file
synchronized with the accepted manuscript. Bibliographic URLs can use that PDF
before a real arXiv identifier is assigned.

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

The social card has an HTML source in `og.html`. With the docs directory
served locally, regenerate it at 1200 by 630 pixels:

```bash
PLAYWRIGHT_CORE=/path/to/playwright-core/index.mjs node docs/_build/make_og_card.mjs http://127.0.0.1:8000/
```
