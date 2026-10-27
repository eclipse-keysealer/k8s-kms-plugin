# Documentation site

The `k8s-kms-plugin` documentation site: [Hugo](https://gohugo.io/) with the
[Hextra](https://github.com/imfing/hextra) theme, published to GitHub Pages by
[`.github/workflows/docs.yml`](../.github/workflows/docs.yml).

`baseURL` in [`hugo.toml`](./hugo.toml) is only the **local-dev default**. The workflow computes it
from the owner and repository actually running the build, so the same config publishes correctly
from a fork and from `eclipse-keysealer` upstream with nothing to remember. Publishing is keyed off
the repository's **default branch**, not a hardcoded `master`, for the same reason. Override the URL
locally the same way:

```sh
cd website && hugo --baseURL https://example.github.io/k8s-kms-plugin/
```

Hextra's "Edit this page" link is **disabled**: it derives the file path from a Hugo internal that
assumes content lives at `<project>/content/`, and with content mounted from `../docs` it splices an
absolute filesystem path into the URL. `hugo.toml` explains it in full.

**The content is not here.** Pages live in [`../docs/`](../docs/README.md) and are *mounted* into
this site by [`hugo.toml`](./hugo.toml), so `docs/` stays the single source of truth and keeps
rendering when browsing the repository on GitHub. To change a page, edit it under `docs/`.

## Build

```sh
make site-serve   # http://localhost:1313/k8s-kms-plugin/ with live reload
make site         # production build -> website/public/, then runs make check-site
make check-site   # verify the built output on its own
make site-clean   # remove public/ and the Hugo caches
```

`make check-site` (`scripts/check-site-output.py`) exists because `hugo` exiting 0 says nothing
about whether the pages work. It verifies that every referenced stylesheet, script, image and page
link is present in the output, that no URL carries the `baseURL` path twice, and that in-page
anchors resolve. Both failures it guards against shipped once: `relativeURLs = true` doubled the
subpath in every asset URL, and unrewritten relative `.md` links 404'd on every cross-page link.

## Local layout overrides

Three files copy or replace theme templates, so each one has to be compared against Hextra's own
version on `hugo mod get -u` and the site rebuilt:

| File | Why |
|------|-----|
| `layouts/_markup/render-link.html` | Hextra's link hook only rewrites destinations beginning with `/`, so a relative `./installation.md` was published verbatim and 404'd |
| `layouts/_markup/render-image.html` | Hextra's image hook skips its `../` compensation when a path already starts with `../`, which broke a diagram once pages moved into a subdirectory |
| `layouts/_partials/navbar-title.html` | Adds the version chip after the site title. Only the block below the marker comment is ours; the rest is the theme's file verbatim |

`layouts/_partials/custom/footer.html` is **not** an override — it fills a hook Hextra calls on
purpose, and needs no attention on upgrade.

## Showing which version the reader is on

Two places answer it: a chip beside the navbar title, and a "Documentation build" line in the footer
carrying version, commit, build date and a link to the workflow run that produced the page.

Both read the same parameters, and none of them is committed — a version baked into the repository is
a version that goes stale:

| Parameter | Local (`make site`) | Published (`docs.yml`) |
|-----------|---------------------|------------------------|
| `docsVersion` | `git describe --tags --always --dirty` | `git describe --tags --always` |
| `docsCommit` | `git rev-parse HEAD` | `github.sha` |
| `docsBuildDate` | `date -u --iso-8601=seconds` | same |
| `docsRunURL` | unset | link to the Actions run |
| `docsRepoURL` | defaults to the upstream repository | `github.server_url/github.repository` |

They arrive as `HUGO_PARAMS_DOCSVERSION` and friends — Hugo's env-var route into site params, whose
lookup is case-insensitive, so `HUGO_PARAMS_DOCSVERSION` reaches `site.Params.docsVersion`. A bare
`hugo` with none of them set is a supported case: the footer says *unversioned local build* and the
chip is omitted, rather than the page implying a version it does not have.

Hextra has no built-in version switcher, and this is not one — there is a single published site, and
what it shows is which commit built it. A reader who needs the docs for an older release reads them
from that release's tag on GitHub.

Hugo does **not** need to be the *extended* build: Hextra v0.12.x ships its Tailwind CSS
precompiled, so there is no SCSS to transpile.

```sh
go install github.com/gohugoio/hugo@v0.164.0
```

## Why this directory exists

Hugo Modules are Go modules. A Hugo project at the repository root would add the theme to the
plugin's own `go.mod`, where it would surface in `go mod tidy`, `NOTICE.md` and `govulncheck` —
none of which should know about a documentation theme. Keeping the site here gives it a separate
[`go.mod`](./go.mod), which pins the theme version with a checksum in `go.sum` and leaves the
plugin's module graph untouched.

## Adding a page

Create the Markdown file under `docs/` and give it front matter:

```yaml
---
title: "Short sidebar label"
weight: 45
---
```

- `title` supplies the page heading — **do not also write an `# H1`** in the body, or the title
  renders twice.
- `weight` orders the sidebar. Current spacing: concepts 10, installation 20, usage 30, crypto 40,
  HSM guides 51–55, Kubernetes guides 61–62, development 70, supply chain 80, CLI reference 90+.
- A `README.md` is *not* a section index to Hugo. It is excluded from the content mount and
  re-mounted as `_index.md`; adding a new directory with a `README.md` means adding a mount for it
  in `hugo.toml`.

Run `make check-doc-links` after moving or renaming anything.

## Alerts

GitHub-style alerts work in **both** renderers, unlike the code-block attributes below: GitHub
renders them natively and Hextra has a blockquote render hook for them. Prefer one over a blockquote
opening with an emoji.

```markdown
> [!WARNING]
> Without `PKCS11_MODULE` both suites exit immediately and successfully.
```

| Type | Hextra colour | Use it for |
|------|---------------|------------|
| `[!NOTE]` | blue | Context, rationale, status ("under construction", why a design choice was made) |
| `[!TIP]` | green | An optional shortcut or an alternative tool |
| `[!IMPORTANT]` | purple | A constraint the reader must satisfy to succeed |
| `[!WARNING]` | amber | A trap that fails silently or misleads |
| `[!CAUTION]` | red | Security or data-loss consequences |

Four rules:

- **Nothing else on the marker line.** A custom title (`> [!NOTE] My title`) is a Hugo feature that
  GitHub does not implement: GitHub stops treating the block as an alert entirely and prints
  `[!NOTE] My title` as ordinary blockquote text.
- **Drop the emoji and the label.** The marker supplies both an icon and a "Warning"/"Note" heading,
  so a leading ⚠️ or a `**Note**:` prefix just says it twice. A bold lead-in that carries real
  content — `**RSA-4096 is close to the ceiling.**` — stays.
- **Only the five types above.** Hextra emits a build warning for anything else and falls back to a
  green box, which is easy to miss in a passing build.
- **Not everything is an alert.** Quoted script output, an attribution, a table caption and this
  documentation's 🙋 "manual step" markers are blockquotes on purpose — colouring them in costs the
  real alerts their signal.

## Code block attributes

Hugo parses a brace block in the fence info string and hands it to Hextra's codeblock render hook.
No `markup.goldmark.parser.attribute` setting is involved — that one is for other block types, and
code fences work without it.

````markdown
```yaml {filename="/tmp/kms-dev/config/kind.config.yaml",linenos=table,hl_lines=[6,18]}
````

| Attribute | Effect |
|-----------|--------|
| `filename` | Renders a filename bar above the block. Use it when the block **is** that file's content, not for commands that merely mention a path |
| `base_url` | Turns the filename bar into a link to `base_url` + `filename`. Only correct when the named file is tracked in the repository — e.g. `base_url="https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/"` with a repo-relative `filename` |
| `linenos=table` | Line numbers in a separate table column. Use `table`, not `inline`: the copy button takes the *last* `<code>` element, so `table` keeps copied text free of line numbers while `inline` would paste them in |
| `hl_lines` | Highlights lines, 1-indexed within the block. Accepts a list (`[6,18]`) or ranges as strings (`["9-15"]`) |

Two rules that keep these useful rather than decorative:

- **The prose must explain the highlight.** These attributes are invisible on GitHub, which renders
  only the first word of the info string and drops the rest — highlighting is therefore a
  site-only affordance. A sentence such as "the highlighted lines are the `rotation` subcommand and
  its `--old-*` flags" reads correctly in both places; an unexplained highlight is noise on the site
  and nothing at all on GitHub.
- **Do not duplicate a path.** A leading `# path/to/file` comment inside the block plus a `filename`
  attribute shows the same path twice on the site. Move the path into the attribute and let the
  surrounding prose carry it for GitHub readers.

## The glossary

Hextra builds a glossary from a Hugo **data** file, not from Markdown: its `glossary` layout reads
`site.Data.<lang>.termbase` and ignores the page body completely. That shape does not fit a
documentation tree that has to keep rendering on GitHub, so the glossary is split in two with one
source:

| File | Role |
|------|------|
| `docs/termbase.yaml` | The source of truth. Mounted by `hugo.toml` at `data/en/termbase.yaml`, and excluded from the content mount so it is not also published as a page resource |
| `docs/glossary.md` | Generated by `make glossary`. Front matter carries `layout: glossary`, so the site renders the styled `<dl>` from the YAML and drops this body — while GitHub renders the body's table |

`make glossary-check` fails if the two disagree, and the Docs workflow runs it. The generator sorts
with a case-insensitive key to match Hugo's collation, so the table's order is the same as the
site's `<dl>`; that equivalence is worth re-checking if Hugo ever changes how `sort` collates.

Two things to know before editing `docs/termbase.yaml`:

- **Quote every value.** An unquoted `#` after a space (`PKCS #11`) silently starts a YAML comment
  and truncates the value; an unquoted `: ` fails the parse outright. Only the second one is loud.
- **Definitions are plain prose.** The theme prints them straight into `<dd>` without running
  Markdown, so backticks and links would appear as literal characters on the published page.

Hextra also ships a `{{</* term "KEK" */>}}` shortcode that renders an `<abbr>` tooltip from the same
data. **Do not use it in `docs/`** — GitHub would show the shortcode call verbatim in the middle of a
sentence. It is only safe in `website/content/`, which is never rendered by GitHub.

## Mermaid and search

Both Mermaid and FlexSearch are fetched **at build time** and re-served from this site with a
Subresource Integrity hash, so published pages never call a CDN at runtime. The versions are pinned
in `hugo.toml`: Hextra's default Mermaid base is `mermaid@latest`, which would otherwise let an
upstream release change what the site ships without a commit here.

For a build with no network access at all, drop the two files into `website/assets/js/`
(git-ignored) and switch the config from `base` to `js`:

```sh
mkdir -p website/assets/js
curl -sSLo website/assets/js/mermaid.min.js \
  https://cdn.jsdelivr.net/npm/mermaid@11.16.1/dist/mermaid.min.js
curl -sSLo website/assets/js/flexsearch.bundle.min.js \
  https://cdn.jsdelivr.net/npm/flexsearch@0.8.143/dist/flexsearch.bundle.min.js
```

```sh
HUGO_PARAMS_MERMAID_BASE="" \
HUGO_PARAMS_MERMAID_JS="js/mermaid.min.js" \
HUGO_PARAMS_SEARCH_FLEXSEARCH_JS="js/flexsearch.bundle.min.js" \
  make site
```

## Upgrading the theme

```sh
cd website && hugo mod get -u github.com/imfing/hextra && hugo mod tidy
```

Then rebuild and check the pages still render — in particular that raw HTML still works
(`markup.goldmark.renderer.unsafe`), since the documentation relies on `<details>` blocks.
