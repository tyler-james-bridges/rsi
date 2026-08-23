# Signed release bundle

`@rsi/release-bundle` creates an optional restorable, signed release companion. The active
single-machine production path uses ordinary reviewed GitHub releases and does not require this
package. When selected as extra software hardening, it packages a closed, sanitized inventory of
source, the frozen lockfile, versioned configuration schemas, runbooks, the recovery procedure,
CycloneDX SBOM, and complete offline test summary.

It never crawls a checkout or accepts a source directory. The release pipeline must
provide each file as an explicit byte artifact, the exact Git commit/tree identity,
and the binding set returned by `deriveReleaseArtifactBindings`. Every input is
copied before the asynchronous signer runs.

The source-tree hash is computed over the canonical sorted descriptors for every
packaged `source` and `lockfile` byte artifact. `gitTreeSha` is a separately signed
Git object identity supplied by the release pipeline; because this package never
crawls Git, that pipeline must prove its explicit inventory is the intended tree.
The config-set hash intentionally uses the same canonical
`rsi.backup.config-schema-hashes` projection as `@rsi/backup`, with each
`schemaSha256` hashing the corresponding packaged versioned-schema artifact bytes.
The bundle format pins the closed schema list in `artifacts.ts`, including the
`sanitized-event-archive` schema.

The signed bundle format is version 2. The generic production-contract and recovery artifact names
replace the retired design's vocabulary as an explicit breaking pre-alpha format change; no
production version-1 bundle was commissioned.

```ts
const bindings = deriveReleaseArtifactBindings(artifacts);

const receipt = await createSignedReleaseBundle({
  artifacts,
  destinationPath: "/absolute/owner-only/release.rsi-release",
  release: {
    ...bindings,
    commitSha,
    createdAt,
    gitTreeSha,
    nodeVersion: "24.19.0",
    pnpmVersion: "11.20.0",
    predecessorManifestSha256,
    releaseVersion,
  },
  signer: {
    keyId,
    publicKeySpkiDer,
    // Key custody stays behind the caller-supplied signing adapter.
    sign: async (domainSeparatedManifest) => signElsewhere(domainSeparatedManifest),
  },
});
```

The signer is dependency-injected. It may use an application-managed key, a
cloud signing service, or another software implementation appropriate to the
deployment. This package receives only the public key metadata and signing
callback, so it does not require a particular computer or physical device.

The returned receipt is not stored inside the archive. Retain it independently on
the verifier plane and require it for every verification or restore. It pins the
whole archive, manifest, bundle ID, lineage, signer, commit/tree, source, lockfile,
SBOM, config, runbook, recovery, test, and artifact-set hashes. Supplying an older
archive with the newest receipt therefore fails before its manifest is trusted.

Publication is create-only and mode `0600`. Verification rejects symlinks,
persistent hardlinks, special files, permissive modes, truncation, change while
reading, noncanonical manifests, unknown fields, semantic downgrades, secret-like
content, or any signature/digest/receipt mismatch. Restore verifies everything
before creating a new mode-`0700` destination and writes every file with
`O_EXCL | O_NOFOLLOW` and mode `0600`; it never overwrites a destination.

This package reports `verified-restorable-release-component`, not complete recovery.
A complete recovery workflow may also select a verified `sanitized-state-evidence` component and
a restorable `sanitized-event-archive`, plus independent target verification and an acceptance
controller. Those optional components do not gate the active staged path. The bundle intentionally excludes raw Vault/index data,
cursors, credentials, state/wrapping/capture keys, `.env` files, and arbitrary
filesystem content.
