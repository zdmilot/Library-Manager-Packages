# Library Manager Packages

Public package repository for **Library Manager for Venus 6**.

## How It Works

This repository serves as the marketplace backend for the Library Manager application. When `.hxlibpkg` files are pushed to the `packages/` directory, a GitHub Actions workflow automatically rebuilds the `catalog.json` manifest that the Library Manager store reads from.

## Adding a Package

1. Place your `.hxlibpkg` file in the `packages/` directory
2. Commit and push
3. The GitHub Action will automatically extract metadata from the package and rebuild `catalog.json`

## Catalog Format

The `catalog.json` file at the repository root is auto-generated and contains an array of package metadata objects. Each entry includes:

- `package_file` — Filename of the `.hxlibpkg` in `packages/`
- `library_name` — Human-readable library name
- `author` — Package author(s)
- `organization` — Author's organization
- `version` — Semantic version string
- `description` — Library description
- `tags` — Array of searchable tags
- `venus_compatibility` — VENUS version compatibility string
- `github_url` — Optional GitHub link
- `created_date` — ISO 8601 creation timestamp
- `library_image_base64` — Base64-encoded icon image
- `library_image_mime` — MIME type of the icon

## Download URLs

Packages are served directly from GitHub raw content:

```
https://raw.githubusercontent.com/zdmilot/Library-Manager-Packages/main/packages/<filename>.hxlibpkg
```

## License

See [LICENSE](LICENSE) for details.
