# Circular Dependencies in cui-java-tools

## Overview
During the Sonar analysis on branch `feature/some_code_maintenance`, three major circular dependency issues were identified. These issues impact maintainability with high severity.

## Identified Issues

### 1. IO Package Cycle
**Location**: `FilenameUtils.java` (line 89)
- Cycle contains 2 classes within `de.cuioss.tools.io`
- Classes involved: `FilenameUtils` and `IOCase`
- Multiple interactions including method calls and field usage

### 2. Collection Package Cycle
**Location**: `CollectionLiterals.java` (line 88)
- Cycle contains 4 classes within `de.cuioss.tools.collect`
- Classes involved:
  * `CollectionLiterals`
  * `MoreCollections`
  * `MapDiffenceImpl`
  * `MapBuilder`
- Complex interaction pattern with multiple cross-dependencies

### 3. SSL Package Cycle
**Location**: `KeyMaterialHolder.java` (line 37)
- Cycle contains 2 classes within `de.cuioss.tools.net.ssl`
- Classes involved: `KeyMaterialHolder` and `KeyStoreProvider`
- Bidirectional dependency through method calls and type usage

## Impact
- All issues are marked as MAJOR severity
- Type: CODE_SMELL
- Impact: HIGH on MAINTAINABILITY
- Rule: javaarchitecture:S7027

## Next Steps
1. Review each cycle to understand the nature of the dependencies
2. Consider refactoring options:
   - Extract shared functionality to break cycles
   - Introduce interfaces to decouple implementations
   - Consider if some dependencies can be inverted
3. Prioritize based on complexity and impact:
   - Two-class cycles may be easier to resolve
   - The collection package cycle involves more classes and may need more careful planning
