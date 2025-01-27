# gh-attest-util

A GitHub Actions utility for generating standardized artifact attestations.

## Usage

### Metadata Attestation

```yaml
- uses: liatrio/gh-attest-util@main
  with:
    type: metadata
    artifact-digest: ${{ needs.build.outputs.image-digest }}
    registry: ghcr.io
```

Generates a standardized metadata attestation including:

- Artifact details (version, digest, registry info)
- Repository context
- Workflow/job information
- Commit data
- Organization details
- Compliance metadata
- Security permissions

### Dependency Scan Attestation WIP

```yaml
- uses: liatrio/gh-attest-util@main
  with:
    type: depscan
    results-file: results.json
```

Transforms Grype scan results into a standardized format containing:

- Scanner metadata
- Database information
- Vulnerability findings with severity scores
- Scan timestamps

## Development

### Schema Generation

The tool uses code generation to create Go structs from JSON schemas. To generate the schema files:

```bash
make generate
```

Requirements:
- GitHub token with repo access (can be obtained via `gh auth token`)
- Set `GITHUB_TOKEN` environment variable or have `gh` CLI authenticated
- Set `POLICY_VERSION` environment variable to use a specific version (optional, defaults to latest release)

The generator will:
1. Fetch schemas from the policy library repository
2. Generate corresponding Go structs
3. Place generated files in the `internal/attestation/schema/generated` directory

Note: Generated files are gitignored and will be regenerated during the build process.
