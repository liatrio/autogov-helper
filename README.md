# autogov-helper

A GitHub Actions utility for generating standardized artifact attestations.

## Usage

### Metadata Attestation

For container images:

```yaml
- name: Generate Metadata Attestation
  env:
    GITHUB_WORKFLOW_INPUTS: ${{ toJson(inputs) }}
  run: |
    ./autogov-helper metadata \
      --type image \
      --subject-name ghcr.io/myorg/myapp:latest \
      --subject-digest sha256:abc123def456 \
      --output metadata.json
```

For blobs (single file or directory):

```yaml
- name: Generate Metadata Attestation
  env:
    GITHUB_WORKFLOW_INPUTS: ${{ toJson(inputs) }}
  run: |
    ./autogov-helper metadata \
      --type blob \
      --subject-path ${{ env.ARTIFACTS_FOLDER }} \
      --output metadata.json
```

Generates a standardized metadata attestation including:

- Artifact details
  - Version, created timestamp
  - Type (container-image or blob)
  - For images: registry, fullName, digest
  - For blobs: path and digest
- Repository data (name, ID, GitHub server URL)
- Owner data (name, ID)
- Runner data (OS, architecture, environment)
- Workflow data (reference path, inputs, branch, event)
- Job data (run number, ID, status, trigger, timestamps)
- Commit data (SHA, timestamp)
- Organization details
- Compliance metadata
- Security permissions
  - For images: id-token:write, attestations:write, contents:read, packages:write
  - For blobs: id-token:write, attestations:write, contents:read, packages:none

### Dependency Scan Attestation

For container images:

```yaml
- name: Generate Dependency Scan Attestation
  run: |
    ./autogov-helper depscan \
      --type image \
      --subject-name ghcr.io/myorg/myapp:latest \
      --subject-digest sha256:abc123def456 \
      --results-path results.json \
      --output depscan.json
```

For blobs (single file or directory):

```yaml
- name: Generate Dependency Scan Attestation
  run: |
    ./autogov-helper depscan \
      --type blob \
      --subject-path ${{ env.ARTIFACTS_FOLDER }} \
      --results-path results.json \
      --output depscan.json
```

Transforms Grype scan results into a standardized format containing:

- Scanner metadata (version, URI)
- Database information (version, last update)
- Vulnerability findings with severity scores
- Scan timestamps
- Standardized severity structure
  - Multiple scoring methods (NVD, CVSS)
  - Normalized severity levels

## Blob Handling

When working with blobs, both commands support:

- Single files
- Directories (all files in the directory will be included)
- Glob patterns (e.g., `*.jar` or `**/*.go`)

For directories and glob patterns, the commands will:

1. Recursively find all files
2. Sort them for consistent ordering
3. Calculate a combined digest

## Policy Repository Configuration

The tool validates attestations against JSON schemas stored in a policy repository. The configuration can be customized using the following environment variables:

- `POLICY_REPO_OWNER`: GitHub organization/owner of the policy repository (default: "liatrio")
- `POLICY_REPO_NAME`: Name of the policy repository (default: "demo-gh-autogov-policy-library")
- `POLICY_VERSION`: Git reference (branch, tag, or commit) to use (default: "main")
- `SCHEMAS_PATH`: Path to the schemas directory in the repository (default: "schemas/")

The tool will first attempt to fetch schemas from the configured policy repository. If that fails (e.g., no GitHub token available or network issues), it will fall back to using embedded schemas.

## Development

Requirements:

- GitHub token with repo access (can be obtained via `gh auth token`)
- Set `GITHUB_TOKEN` environment variable or have `gh` CLI authenticated

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
docker pull ghcr.io/liatrio/autogov-helper:latest

# Pull a specific version
docker pull ghcr.io/liatrio/autogov-helper:v1.0.0

# Run the container
docker run --rm ghcr.io/liatrio/autogov-helper:latest --help
```

Container images are automatically built and pushed to GitHub Container Registry (GHCR) on each release.

## License

Copyright 2025 The Liatrio Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
