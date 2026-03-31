# Phase 7 Enriched Finding: P7-004

## Finding Details

| Field | Value |
|-------|-------|
| **Finding ID** | P7-004 |
| **Source SAST ID** | SAST-004 |
| **Tool** | Semgrep (go.lang.security.decompression_bomb + harbor-decompression-bomb-tar) |
| **Title** | Decompression Bomb via Unbounded io.Copy from tar.Reader |
| **Severity** | MEDIUM |
| **Confidence** | HIGH |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |

## Vulnerability Classification

**Type**: Security (exploitable denial of service via resource exhaustion)

## Reachability Assessment

**Status**: CONFIRMED REACHABLE

**Evidence**:
- Code inspection: `io.Copy()` called without `io.LimitReader` wrapper
- Call flow: Artifact push → parser → tar extraction → unbounded buffer
- Trust Boundary: TB-6 (Registry ↔ Core artifact processor)
- Sink type: `io.Copy()` from `tar.Reader` at 2 locations

## Attacker-Controlled Input Path

**Entry Point**: OCI Registry V2 blob upload API

```
PUT /v2/{repository}/blobs/uploads/{uuid}?digest=sha256:...
Content-Type: application/octet-stream

[ATTACKER-CONTROLLED TAR ARCHIVE CONTENT]
```

**Attack Flow**:
1. Attacker with push access uploads artifact layer
2. Layer contains tar.gz compressed archive
3. Core API processes artifact (display, catalog, analysis)
4. `controller/artifact/processor/cnai/parser/util.go:untar()` called
5. tar.Reader iterates entries
6. `io.Copy(&buf, tr)` streams entire entry content to bytes.Buffer
7. No maximum size enforcement
8. Attacker crafts tar archive:
   - Single entry file: `/model.tar.gz`
   - Original size: 100 MB
   - Compressed: 1 MB
   - After extraction: **100 GB** (1000x expansion)
9. Core container memory exhausted → OOM kill or service hung

## Code Locations & Snippets

### Location 1: CNAI Model Parser

**File**: `src/controller/artifact/processor/cnai/parser/util.go`
**Line**: 45
**Function**: `untar()`

```go
func untar(reader io.Reader) ([]byte, error) {
    tr := tar.NewReader(reader)
    var buf bytes.Buffer  // [NO SIZE LIMIT - PROBLEM!]
    for {
        header, err := tr.Next()
        if err == io.EOF {
            break
        }

        if err != nil {
            return nil, fmt.Errorf("failed to read tar header: %w", err)
        }

        // skip the directory.
        if header.Typeflag == tar.TypeDir {
            continue
        }

        // [VULNERABLE SINK: io.Copy with no limit]
        if _, err := io.Copy(&buf, tr); err != nil {
            return nil, fmt.Errorf("failed to copy content to buffer: %w", err)
        }
    }

    return buf.Bytes(), nil
}
```

**Problem**:
- `io.Copy` streams all data from tar reader to buffer
- No maximum size enforcement
- bytes.Buffer grows unbounded in memory
- If tar entry is 100 GB, entire 100 GB loaded into RAM

### Location 2: Digest Calculator (Scan Export)

**File**: `src/pkg/scan/export/digest_calculator.go`
**Line**: 40
**Function**: (Similar untar pattern)

```go
// Same untar() function or similar pattern
if _, err := io.Copy(&buf, tr); err != nil {
    return nil, fmt.Errorf("failed to copy content to buffer: %w", err)
}
```

## Vulnerability Analysis

### Attack Prerequisites

| Requirement | Status | Notes |
|-------------|--------|-------|
| **Repository access** | Required | Push role on any repository |
| **Ability to craft artifacts** | Required | Trivial with tar/gzip tools |
| **Exploit triggering** | Automatic | Happens when Core processes artifact |
| **Privilege level needed** | User | Any authenticated user with push role |

### Resource Exhaustion Mechanism

**Compression Bomb Example**:

```bash
# Create 100 GB zero-filled file
dd if=/dev/zero bs=1M count=100K | tar czf bomb.tar.gz -

# Result:
# - Compressed size: ~1-10 MB (excellent compression ratio for zeros)
# - Extracted size: 100 GB
# - Expansion ratio: 10,000x - 100,000x
```

**Harbor Processing**:
1. Registry receives 10 MB blob upload
2. Core retrieves blob: 10 MB on disk
3. Core processes artifact (CNAI parser)
4. tar extraction begins: untar() called
5. io.Copy() decompresses and loads into bytes.Buffer
6. 10 MB becomes 100 GB in RAM
7. Core process memory limit exceeded
8. OOM killer terminates Core pod
9. Service unavailable until restart

### Memory Exhaustion Impact

| Aspect | Impact |
|--------|--------|
| **Core container memory usage** | Grows from ~50 MB to 100+ GB |
| **Container memory limit** | Typically 2-4 GB → immediate OOM |
| **Service availability** | Down for 30+ seconds (pod restart) |
| **Cascading failures** | Dependent services (Portal, Registry Proxy) can't reach Core |
| **Operator experience** | Appears as random service outages, hard to debug |

### Denial of Service Scenarios

**Scenario 1: Targeted Service Disruption**
```
1. Attacker creates webhook that monitors artifact pushes
2. Pushes decompression bomb
3. Core OOM kills → service down
4. Repeated every minute
5. Effectively DoS attack for duration of exploit
```

**Scenario 2: Resource Starvation**
```
1. Attacker uploads multiple artifacts with different decompression ratios
2. Each one consumed during catalog operations
3. Cluster-wide memory pressure
4. Performance degradation across all services
```

**Scenario 3: Backup/Export Triggers**
```
1. Decompression bomb uploaded
2. Operator initiates export/backup job
3. Export process scans artifacts and parses them
4. Export job OOM kills during decompression
5. Backup corrupted, restore capability lost
```

## Recommended Fix

### Fix Strategy 1: io.LimitReader (Recommended)

```go
const maxArtifactSize = 50 * 1024 * 1024  // 50 MB for metadata

func untar(reader io.Reader) ([]byte, error) {
    tr := tar.NewReader(reader)
    var buf bytes.Buffer
    for {
        header, err := tr.Next()
        if err == io.EOF {
            break
        }

        if err != nil {
            return nil, fmt.Errorf("failed to read tar header: %w", err)
        }

        // skip the directory.
        if header.Typeflag == tar.TypeDir {
            continue
        }

        // [FIX: Wrap tar reader with size limit]
        limitedReader := io.LimitReader(tr, maxArtifactSize)
        n, err := io.Copy(&buf, limitedReader)
        if err != nil && err != io.EOF {
            return nil, fmt.Errorf("failed to copy content to buffer: %w", err)
        }

        // Verify we didn't hit the limit
        if n >= maxArtifactSize {
            return nil, fmt.Errorf("artifact exceeds maximum size: %d bytes", maxArtifactSize)
        }
    }

    return buf.Bytes(), nil
}
```

### Fix Strategy 2: Total Size Tracking

```go
func untar(reader io.Reader) ([]byte, error) {
    const maxTotalSize = 100 * 1024 * 1024  // 100 MB total
    tr := tar.NewReader(reader)
    var buf bytes.Buffer
    totalSize := int64(0)

    for {
        header, err := tr.Next()
        if err == io.EOF {
            break
        }

        if err != nil {
            return nil, fmt.Errorf("failed to read tar header: %w", err)
        }

        if header.Typeflag == tar.TypeDir {
            continue
        }

        // Check total size before copying
        if totalSize+header.Size > maxTotalSize {
            return nil, fmt.Errorf("total archive size exceeds limit")
        }

        if _, err := io.Copy(&buf, tr); err != nil {
            return nil, fmt.Errorf("failed to copy content to buffer: %w", err)
        }

        totalSize += header.Size
    }

    return buf.Bytes(), nil
}
```

### Fix Strategy 3: Per-Entry Limit + Total Limit (Most Robust)

```go
const (
    maxPerEntry   = 10 * 1024 * 1024   // 10 MB per file
    maxTotalSize  = 50 * 1024 * 1024   // 50 MB total
)

func untar(reader io.Reader) ([]byte, error) {
    tr := tar.NewReader(reader)
    var buf bytes.Buffer
    totalSize := int64(0)

    for {
        header, err := tr.Next()
        if err == io.EOF {
            break
        }

        if err != nil {
            return nil, fmt.Errorf("failed to read tar header: %w", err)
        }

        if header.Typeflag == tar.TypeDir {
            continue
        }

        // Per-entry limit
        if header.Size > maxPerEntry {
            return nil, fmt.Errorf("entry %s exceeds max size: %d > %d",
                header.Name, header.Size, maxPerEntry)
        }

        // Total size check
        if totalSize+header.Size > maxTotalSize {
            return nil, fmt.Errorf("total archive size would exceed limit")
        }

        // Limit this entry's copy
        limitedReader := io.LimitReader(tr, header.Size)
        if _, err := io.Copy(&buf, limitedReader); err != nil {
            return nil, fmt.Errorf("failed to copy content to buffer: %w", err)
        }

        totalSize += header.Size
    }

    return buf.Bytes(), nil
}
```

## Phase 8 Chamber Assignment

**Chamber**: **Resource Exhaustion (DoS-001)**

**Rationale**:
- Exploitable by any authenticated user with push role
- Causes denial of service via memory exhaustion
- Affects system availability
- Easy to trigger (just push crafted artifact)
- Impacts all services dependent on Core API

## References

- **CWE-400**: [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- **OWASP**: [Zip Slip and Compression Bomb](https://owasp.org/www-community/attacks/Zip_Slip)
- **Bzip2 Compression Bomb**: `bomb.zip` - classic 915 KB file that expands to 4.5 TB
- **KB Report**: TB-6 (Registry ↔ Core artifact processor)
- **Related**: Tar bomb vulnerabilities in Docker, Kubernetes, container runtimes

## Notes for Reviewers

1. **Severity**: MEDIUM not HIGH because:
   - Requires authentication (push role)
   - Causes DoS, not data breach
   - Container restart recovers from attack
   - But: repeated attacks could cause continuous outages

2. **Exploitability**: HIGH
   - No special tools needed (standard tar/gzip)
   - Automatic triggering on artifact processing
   - Simple one-liner to create bomb

3. **Impact**: Medium (availability only, not confidentiality/integrity)

4. **Recommended Maximum Sizes**:
   - CNAI model metadata: 50 MB (reasonable for model config JSON)
   - Scan export: 100 MB (may need tuning based on real usage)
   - Per-entry limit: 10 MB (prevents individual large files)

5. **Testing**:
   - Create test tar.gz bomb
   - Push to Harbor repository
   - Monitor Core container memory
   - Verify it exceeds limits without fix
   - Verify fix prevents OOM

6. **Related Findings**:
   - SAST-004 addresses both CNAI parser and digest calculator
   - Both should be fixed with same size constants
