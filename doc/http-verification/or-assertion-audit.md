# QI-9: OR-Assertion Anti-Pattern Audit

## Problem Statement

Attack tests use broad OR-assertion patterns that accept multiple failure types, making it impossible to:
1. **Verify specific security validation** - Can't tell which validation rule triggered
2. **Detect false positives** - Wrong validation passing allows real attacks through
3. **Debug test failures** - Unclear which security mechanism failed
4. **Ensure test precision** - Tests become too permissive

## Examples Found

### CompressionBombAttackTest
**Method**: `isCompressionBombRelatedFailure()`
**Accepts**: 7 different failure types
- `INPUT_TOO_LONG`
- `PATH_TOO_LONG` 
- `SUSPICIOUS_PATTERN_DETECTED`
- `KNOWN_ATTACK_SIGNATURE`
- `INVALID_CHARACTER`
- `EXCESSIVE_NESTING`
- `MALFORMED_INPUT`

**Problem**: A ZIP bomb should trigger `KNOWN_ATTACK_SIGNATURE`, but test passes if it triggers `INPUT_TOO_LONG` instead, masking that the ZIP detection didn't work.

### HttpRequestSmugglingAttackTest
**Method**: `isRequestSmugglingRelatedFailure()`
**Accepts**: 7 different failure types
- `CONTROL_CHARACTERS`
- `INVALID_CHARACTER`
- `MALFORMED_INPUT`
- `SUSPICIOUS_PATTERN_DETECTED`
- `INVALID_ENCODING`
- `PROTOCOL_VIOLATION`
- `RFC_VIOLATION`

## Solution Approach

### Phase 1: Attack-Specific Failure Mapping
Create specific failure type expectations for each attack category:

1. **ZIP Bombs** → `KNOWN_ATTACK_SIGNATURE`
2. **Gzip Bombs** → `KNOWN_ATTACK_SIGNATURE`  
3. **Nested Compression** → `EXCESSIVE_NESTING`
4. **Memory Exhaustion** → `INPUT_TOO_LONG`
5. **Path Traversal** → `PATH_TRAVERSAL_DETECTED`
6. **Request Smuggling** → `PROTOCOL_VIOLATION`

### Phase 2: Replace OR-Assertions
Replace broad `isXxxRelatedFailure()` methods with specific assertions:

```java
// Before: Accepts 7 different types
assertTrue(isCompressionBombRelatedFailure(exception.getFailureType()));

// After: Specific validation
assertEquals(UrlSecurityFailureType.KNOWN_ATTACK_SIGNATURE, exception.getFailureType(),
    "ZIP bomb should trigger signature detection");
```

### Phase 3: Attack-Specific Test Methods
Split complex tests into attack-specific methods with precise assertions:

```java
@Test
void shouldDetectZipBombsAsAttackSignature() {
    // Only ZIP bomb patterns
    // Assert: KNOWN_ATTACK_SIGNATURE
}

@Test  
void shouldDetectNestedCompressionAsExcessiveNesting() {
    // Only nesting patterns  
    // Assert: EXCESSIVE_NESTING
}
```