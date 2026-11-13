# authgo-pack

Independent, standard-library-only Go 1.26 module. Build **on a build host**:

```sh
# At the repository root; builds/embeds static linux amd64 + arm64 launchers first.
make build-pack
make test-pack
```

See [Docker integration guide](../server/internal/apidocs/docker.md) for current encryption commands. Packaging requires a
**new** `--out` directory with an existing parent. `--verify --out DIRECTORY`
checks only metadata/schema and ciphertext lengths; it does **not** authenticate
ciphertext and does not contact the server. Never treat it as license validation.
The authoritative wire format and public synthetic vector are in
[protocol specification](../server/internal/apidocs/protocol.md) and `sdk/vectors/payload-envelope.json`.

- Prepare Python bytecode in a separate release staging directory first. Only
  CPython 3.8–3.14 final-release bytecode magic values are accepted; all files must
  use the same version. Source `.py`, `.so`, `.pyd` and symlinks are rejected.
- Node input is `.cjs` or CommonJS `.js`. A conservative bounded-memory lexical
  scan rejects ESM import/export tokens and `.node` references, including in
  comments/strings; this is not a complete JavaScript dependency resolver. Bundle
  dependencies first. Dynamically computed native loads cannot be certified by
  a static source scan and are unsupported.
- Java input must be a readable ZIP/JAR with safe, unique, non-symlink entries.
  `Main-Class` supports manifest continuation lines. The JAR bytes are unchanged.
- .NET input must be an IL-only PE with a CLR header and metadata signature.
  Mixed-mode/native inputs and native assets in accompanying `.deps.json` are
  rejected. A sibling `<assembly>.deps.json`, if present, is included in the tar.
- PHP archives contain only `.php` files. Python/PHP non-code data is neither
  encrypted nor deleted. Directory archives are deterministic USTAR streams;
  paths too long for USTAR fail safely rather than producing unsafe extensions.
- `--protect` validates ELF64 little-endian amd64/arm64 executable permissions,
  writes ciphertext/metadata to `--out`, and atomically replaces the input with
  its architecture-matched embedded launcher plus authenticated encrypted program.
  Missing launchers fail without changing the input. Unit tests can inject a
  synthetic ELF; runnable integration tests must use the real embedded launcher.

Code files are removed only after ciphertext and metadata have been fsynced and
published with a same-filesystem directory rename. Before publication, originals
are renamed to private rollback slots in their own directories. Ordinary I/O
failures trigger rollback; open source FDs permit streaming restoration if an
unlink in cleanup fails. Input directories and data files are retained. Operate
on a quiescent build staging tree: do not concurrently mutate sources or output
parents. Existing output is never intentionally overwritten. No multi-filesystem
operation can promise all-or-nothing recovery from power loss, SIGKILL, or a
filesystem that also refuses rollback; on a rollback failure the fixed error
asks the operator to retain the filesystem and inspect `.authgo-input-*` slots.
Content keys are never printed or persisted.

Tests include every binding, cross-build/file block substitution, reordering,
truncation, empty streams, random access, input/path validation, transactional
failure and a real 2 GiB streaming encrypt/decrypt run. The latter samples Go
heap and Linux RSS while processing 8 MiB and 2 GiB, asserts bounded memory, and
removes both input/ciphertext files. It runs by default, even with `-short`.
The independent `testdata/verify-vector.cjs` check uses only Node built-in crypto
and independently derives and verifies all vector values.

## Local watermark trace

```sh
authgo-pack trace --tag '<32 lowercase hex software tag>' leaked-file
# Include all retained key IDs' tags when inspecting a mixed/old build:
authgo-pack trace --tag '<old tag>' --tag '<current tag>' leaked.jar
```

Tracing is read-only and does not need the server or a private key. It streams
raw files, retaining 95 bytes between chunks, and scans verified ZIP/JAR entries
(including nested JARs), not the compressed parent bytes. Fixed safety bounds:
512 MiB cumulative expanded bytes, 128 MiB per entry, depth 4 (root archive is 0),
4096 entries and 4096 distinct nonzero values. CRC, size, bounds and unsupported
ZIP features fail to an explicitly incomplete result, preserving earlier fully
verified entries. Unsupported non-ZIP formats are scanned as raw bytes with a
warning; they are not implicitly decompressed.

JSON statuses: `found`, `zero`, `none`, `ambiguous`, `partial`, `cancelled`.
Zero slots cannot identify a license. A unique highest-frequency **nonzero**
value wins; a tie is ambiguous and must not auto-query a license. Complete
results exit 0, partial/cancelled results exit 2, invalid parameters/input exit 1.
Go and the browser run the same `sdk/vectors/watermark.json` scan cases.

Current encryption emits payload v2 with an independently encrypted watermark index.
The public layout manifest is authenticated. All protected loaders require signed
watermark material and a bound encrypted cache. Configuration is compiled into the
program, production endpoints require HTTPS, and expired or explicitly refused
licenses never fall back to cached authorization.
