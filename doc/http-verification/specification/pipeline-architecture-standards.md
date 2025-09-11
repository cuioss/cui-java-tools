# HTTP Security Pipeline Architecture Standards

## Pipeline Selection Decision Matrix

This document establishes the authoritative standards for selecting appropriate validation pipelines in HTTP security attack database testing.

### URLPathValidationPipeline - Path-Focused Attacks

**Purpose**: Validates URL path components, directory traversal, and host-based attacks.

**Use When**:
- Attack patterns target **path components only** (no protocol prefix)
- Directory traversal attacks (`../../../etc/passwd`)
- Host/domain-based exploits
- CVE exploits targeting specific server path handling
- IPv6 address parsing in path context

**Current Implementations**:
- ✅ `ApacheCVEAttackDatabaseTest` - Apache-specific path exploits
- ✅ `HomographAttackDatabaseTest` - Domain spoofing attacks
- ✅ `IISCVEAttackDatabaseTest` - IIS path handling exploits  
- ✅ `IPv6AttackDatabaseTest` - IPv6 path parsing attacks
- ✅ `NginxCVEAttackDatabaseTest` - Nginx path handling exploits
- ✅ `OWASPTop10AttackDatabaseTest` - Path traversal focused

**Attack Pattern Examples**:
```
"/../../../etc/passwd"
"[::ffff:127.0.0.1]/../../../etc/passwd" 
"/admin/..\\..\\windows\\system32"
```

### HTTPBodyValidationPipeline - Content-Focused Attacks

**Purpose**: Validates HTTP request body content, full URLs, and script injection.

**Use When**:
- Attack patterns contain **full URLs with protocols** (`http://`, `https://`)
- XSS and script injection attacks
- Content-based validation (form data, JSON, etc.)
- Full URL parsing required (including domain validation)

**Current Implementations**:
- ✅ `IDNAttackDatabaseTest` - Full URL homograph attacks with protocols
- ✅ `XssInjectionAttackDatabaseTest` - Script injection in body content

**Attack Pattern Examples**:
```
"http://аpple.com/../../../etc/passwd"
"<script>alert('XSS')</script>"
"/admin?q=<script>alert('XSS')</script>"
```

## Architectural Principles

### 1. Protocol Presence Rule
- **Full URLs with protocol** → `HTTPBodyValidationPipeline`
- **Path-only patterns** → `URLPathValidationPipeline`

### 2. Content Type Priority
- **Script/HTML injection** → `HTTPBodyValidationPipeline`
- **Path traversal/CVE exploits** → `URLPathValidationPipeline`

### 3. Unicode Handling
- **Unicode domains in full URLs** → `HTTPBodyValidationPipeline`
- **Unicode characters in paths** → `URLPathValidationPipeline` with `allowHighBitCharacters(true)`

### 4. Configuration Requirements

#### URLPathValidationPipeline Configuration
```java
SecurityConfiguration config = SecurityConfiguration.defaults();
// Standard configuration for most path-based attacks

// For Unicode path content:
SecurityConfiguration config = SecurityConfiguration.builder()
    .allowHighBitCharacters(true)
    .build();
```

#### HTTPBodyValidationPipeline Configuration  
```java
// For IDN attacks (full URLs with Unicode):
SecurityConfiguration config = SecurityConfiguration.builder()
    .allowHighBitCharacters(true)
    .failOnSuspiciousPatterns(true)
    .build();

// For standard XSS attacks:
SecurityConfiguration config = SecurityConfiguration.defaults();
```

## Quality Assurance Standards

### Test Validation Requirements
1. **Pipeline Selection Verification**: Each test class must use the correct pipeline based on attack pattern type
2. **Expected Failure Type Accuracy**: Test expectations must align with pipeline detection capabilities
3. **Configuration Consistency**: Pipeline configuration must support the attack patterns being tested
4. **Documentation Alignment**: Test class documentation must accurately describe pipeline selection rationale

### Architecture Compliance Checklist
- [ ] Attack patterns analyzed for protocol presence
- [ ] Pipeline selection matches content type (path vs full URL)
- [ ] Unicode handling configured appropriately
- [ ] Expected failure types align with pipeline capabilities
- [ ] Test documentation explains pipeline selection rationale

## Implementation History

**QI-21 Pipeline Architecture Optimization** (Phase 1):
- ✅ Comprehensive audit of all 8 attack database test classes completed
- ✅ Pipeline selection decision matrix established
- ✅ All pipeline assignments verified as architecturally correct
- ✅ No pipeline mismatches identified after thorough analysis

**Key Finding**: Initial analysis incorrectly identified IDNAttackDatabase as pipeline mismatch. Detailed examination revealed that IDN attacks use **full URLs with protocols** (`"http://аpple.com/../../../etc/passwd"`), making HTTPBodyValidationPipeline the correct choice for full URL parsing and Unicode domain validation.

## Future Considerations

1. **New Attack Database Integration**: Follow this decision matrix when adding new attack databases
2. **Pipeline Enhancement**: Consider specialized pipelines for emerging attack vectors
3. **Performance Optimization**: Monitor pipeline performance with large attack databases
4. **Security Standards Evolution**: Update standards as HTTP security threats evolve

---
*Document Version: 1.0*  
*Last Updated: QI-21 Pipeline Architecture Optimization*  
*Maintained by: HTTP Security Validation Framework Team*