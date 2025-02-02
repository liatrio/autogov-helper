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

### VSA Verification

```bash
gh-attest-util vsa --vsa attestation.vsa.json --level 3
```

Verifies a Verification Summary Attestation (VSA) against SLSA v1.0 build levels (L0-L3). Features:

- Validates VSA format and structure
- Verifies SLSA build level compliance
- Supports all SLSA v1.0 build track levels (L0-L3)
- Validates verifier authenticity
- Optional output of verified VSA

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
# Show all available commands
make help

# Run all tests with coverage
make test

# Build the binary with version info
make build

# Format code and run linter
make format lint

# Clean build artifacts
make clean

# Install binary system-wide
make install

# Run all quality checks (format, lint, test)
make verify
```

### Container Image

The utility is also available as a multi-architecture container image:

```bash
# Pull the latest version
docker pull ghcr.io/laitrio/gh-attest-util:latest

# Pull a specific version
docker pull ghcr.io/laitrio/gh-attest-util:v1.0.0

# Run the container
docker run --rm ghcr.io/laitrio/gh-attest-util:latest --help
```

Container images are automatically built and pushed to GitHub Container Registry (GHCR) on each release.
