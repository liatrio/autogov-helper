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
- Repository data (name, ID, GitHub server URL)
- Owner data (name, ID)
- Runner data (OS, architecture, environment)
- Workflow data (reference path, inputs, branch, event)
- Job data (run number, ID, status, trigger, timestamps)
- Commit data (SHA, timestamp)
- Organization details
- Compliance metadata
- Security permissions

### Dependency Scan Attestation

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

Requirements:
- GitHub token with repo access (can be obtained via `gh auth token`)
- Set `GITHUB_TOKEN` environment variable or have `gh` CLI authenticated
- Set `POLICY_VERSION` environment variable to use a specific version (defaults to v0.8.0)

### Building and Testing

```bash
# Run all tests
make test

# Build the binary
make build

# Format code and run linter
make format lint

# Clean build artifacts
make clean
```
