# Building the project page

The page is served from `main:/docs` at `/spillway/`.

## Latest evaluation display (18 November 2026)

Build the current project-page results and verify their visible table cells:

```bash
PYTHONPATH=src python docs/_build/build_current_view.py
python benchmarks/scripts/check_current_results.py
```

The display reads `benchmarks/results/evaluation_20261118.json`, which binds the
final manuscript tables to the checked standard-attack, PISmith and AgentDyn
integer-count receipts. It retains the existing page design and the earlier
component and cost cohorts. The AgentDyn rows use the trusted native integration
and three repeats with agent seed 42. The optional local judge and identity-target
recovery are enabled in the measured full-system profile; SDK defaults are unchanged.

`build_release014_view.py` and its tests reproduce the archived 1.0.0 display.
The instructions below describe that archived builder and its immutable inputs.


Run the checks with Python 3.12 or newer and the dev and AgentDojo extras:

```bash
PYTHONPATH=src python docs/_build/capture_checks.py
PYTHONPATH=src python docs/_build/test_release014_view.py
PYTHONPATH=src python docs/_build/build_release014_view.py
```

The release display reads `benchmarks/results/release_014_actual.json` for SPILLWAY's
standard, stress and four AgentDojo routing rows. It first runs the original 590 paper-data checks, then
updates a private display copy. Comparison methods, three AgentDyn routing rows, ablations and cost measurements
retain their paper records. The mixed seven-suite mean combines four current
AgentDojo rows with the three historical AgentDyn rows; it is not a new seven-suite run.
Scatter positions use exact count-derived means, separately from three-decimal labels. To build the original
paper view separately, run `build_page.py --out /tmp/spillway-paper/index.html`.

The SDK suite checks the 1.0.0 implementation, which preserves the runtime measured in 0.1.4 with release metadata changes and unchanged experimental identities. The display builder labels current results as 1.0.0 and records the original measurement version, wheel identity and actual-report SHA separately. The final capture command, `spillway_guard.agentdojo.runner --legacy-v1 --self-test`, checks the pinned historical reference's original decision and reason strings. It is a parity check rather than a model measurement. The bare historical `--self-test` expects legacy reason strings and is incompatible with the enhanced wrapper.

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

Its manifest pins the input page and each picture. `PYPI_README_100.md` is the immutable published 1.0.0
distribution description (`PYPI_README.md` remains the historical-check input), with absolute image URLs and the
registry install command. Upload the distribution only after the public links
work. After uploading, verify a fresh registry install before enabling the
registry tabs in `publication.json`.

The social cards have an HTML source in `og.html`. `assets/og-card.png`, 1200 by
630 pixels, is an optional share image; the page currently uses the released video cover. `assets/social-card-1280x640.png` is the
repository's social preview, which GitHub takes only as an upload in the
repository settings. With the docs directory served locally, regenerate both:

```bash
PLAYWRIGHT_CORE=/path/to/playwright-core/index.mjs node docs/_build/make_og_card.mjs http://127.0.0.1:8000/
```

`build_page.py` also writes `integrate.html`. The results and integration pages
take the product header, with its maker link, and the footer from the rendered
home page.
`try/make_try.py` composes `docs/try.html` from the built `integrate.html` and copies the released wheel to `docs/wheels/`. Run it after a page build, with the wheel's path as its second argument.
The current browser demo loads `docs/wheels/spillway_guard-1.0.0-py3-none-any.whl` and verifies its SHA-256 and runtime version. Preserve those guards when rebuilding it; a page-only build does not rebuild the SDK wheel.
Their small navigation helper is `assets/subpage.js`. Keep these shared routes
and the current page marker covered when adding a page.

The runnable app examples under `docs/examples/` are checkout documentation.
They exercise the 1.0.0 API and are excluded from the wheel and source
distribution together with the rest of `docs/`.

## Current figure exports

`assets/CURRENT_FIGURES.json` binds the current paper-figure exports to the
actual measurement report and lists the plotted coordinates. Figure 1 updates
only SPILLWAY's four points; the 28 comparison points retain paper precision.
Its five direct ASR labels leave the point positions, axes and scales unchanged.
Figure 4 updates only SPILLWAY's four AgentDojo utility bars. AgentDyn's three
rows, all peer rows, the all-zero ASR panel, architecture and cost figure are
preserved. SVG exports are produced from the matching PDF with
`pdftocairo -svg INPUT.pdf OUTPUT.svg`; the PDF identities are in the manifest.

The complete 54-condition count/profile table is generated on `results.html`
from the immutable actual report. The default SDK configures no judge and
disables identity-target recovery; the displayed full-system profile enables
both. Explicit recovery-OFF measurements remain separate rows.
