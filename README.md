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

## Predicate Structure

The `predicates` directory contains JSON examples of the attestation formats:

### metadata.json
Represents the metadata attestation structure for GitHub Actions workflows, including:
- Basic artifact information (version, type, etc.)
- GitHub repository details
- Workflow and job information
- Runner environment details
- Commit information

### depscan.json
Represents the dependency scan attestation structure for vulnerability scanning, including:
- Scanner information
- Database details
- Vulnerability results

These JSON files serve as:
1. Documentation of the predicate structure
2. Examples for validation
3. References for future updates

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
