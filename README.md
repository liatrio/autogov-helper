# gh-attest-util

A general purpose utility for GitHub Artifact Attestations

makes this:

```yaml
- name: Generate Metadata Attestation
shell: bash
env:
    GITHUB_CONTEXT: ${{ toJson(github) }}
run: |
    VERSION="${GITHUB_SHA:0:7}-${GITHUB_RUN_NUMBER}"

    cat << EOF > metadata.json
    {
    "artifact": {
        "version": "${VERSION}",
        "digest": "${{ needs.build-high-perms.outputs.image-digest }}",
        "created": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "type": "container-image",
        "registry": "${{ inputs.registry }}",
        "fullName": "${{ inputs.registry }}/${{ github.repository }}@${{ needs.build-high-perms.outputs.image-digest }}"
    },
    "repositoryData": {
        "repository": "${{ github.repository }}",
        "repositoryId": "${{ github.repository_id }}",
        "githubServerURL": "${{ github.server_url }}"
    },
    "ownerData": {
        "owner": "${{ github.repository_owner }}",
        "ownerId": "${{ github.repository_owner_id }}"
    },
    "runnerData": {
        "os": "${{ runner.os }}",
        "arch": "${{ runner.arch }}",
        "environment": "${{ runner.environment }}"
    },
    "workflowData": {
        "workflowRefPath": "${{ github.workflow_ref }}",
        "inputs": ${{ toJson(inputs) }},
        "branch": "${{ github.ref_name }}",
        "event": "${{ github.event_name }}"
    },
    "jobData": {
        "runNumber": "${{ github.run_number }}",
        "runId": "${{ github.run_id }}",
        "status": "${{ job.status }}",
        "triggeredBy": "${{ github.actor }}",
        "startedAt": "${{ github.event.workflow_run.created_at }}",
        "completedAt": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    },
    "commitData": {
        "sha": "${{ github.sha }}",
        "timestamp": "${{ github.event.head_commit.timestamp }}"
    },
    "organization": {
        "name": "${{ github.repository_owner }}"
    },
    "compliance": {
        "policyRef": "https://github.com/liatrio/demo-gh-autogov-policy-library",
        "controlIds": [
        "${{ github.repository_owner }}-PROVENANCE-001",
        "${{ github.repository_owner }}-SBOM-002",
        "${{ github.repository_owner }}-METADATA-003"
        ]
    },
    "security": {
        "permissions": {
        "id-token": "write",
        "attestations": "write",
        "packages": "write",
        "contents": "read"
        }
    }
    }
    EOF

    echo "Generated metadata:"
    cat metadata.json | jq '.'
```

and this:

```yaml
- name: Generate Predicate JSON
run: |
    # Load values from results.json
    SCANNER_VERSION=$(jq -r '.descriptor.version' results.json)
    SCANNER_URI="https://github.com/anchore/grype/releases/tag/v$SCANNER_VERSION"
    DB_URI=$(jq -r '.descriptor.configuration.db."update-url"' results.json)
    DB_VERSION=$(jq -r '.descriptor.db.schemaVersion' results.json)
    DB_LAST_UPDATE=$(jq -r '.descriptor.db.built' results.json)
    SCAN_STARTED_ON=$(jq -r '.descriptor.db.built' results.json)
    SCAN_FINISHED_ON=$(jq -r '.descriptor.timestamp' results.json)

    # Collect vulnerabilities with updated severity structure
    jq -n --arg scannerUri "$SCANNER_URI" \
        --arg scannerVersion "$SCANNER_VERSION" \
        --arg dbUri "$DB_URI" \
        --arg dbVersion "$DB_VERSION" \
        --arg dbLastUpdate "$DB_LAST_UPDATE" \
        --arg scanStartedOn "$SCAN_STARTED_ON" \
        --arg scanFinishedOn "$SCAN_FINISHED_ON" \
        --argjson results "$(jq '[.matches[] | {
            id: .vulnerability.id,
            severity: [
            { "method": "nvd", "score": .vulnerability.severity },
            { "method": "cvss_score", "score": (.vulnerability.cvss[0].metrics.baseScore | tostring) }
            ]
        }]' results.json)" \
        '{
            scanner: {
            uri: $scannerUri,
            version: $scannerVersion,
            db: {
                uri: $dbUri,
                version: $dbVersion,
                lastUpdate: $dbLastUpdate
            },
            result: $results
            },
            metadata: {
            scanStartedOn: $scanStartedOn,
            scanFinishedOn: $scanFinishedOn
            }
        }' > dep-scan.json
    echo "Generated dependency scanning results:"
    cat dep-scan.json | jq '.'
```

...easier to work with.
