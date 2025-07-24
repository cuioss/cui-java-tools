# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cui-java-tools is a Java utility library providing essential tools for collections, strings, I/O, logging, and networking. It serves as a zero-dependency replacement for parts of Guava and Apache Commons, following Jakarta EE standards.

### Key Features
- Zero external dependencies (only Lombok for development)
- Comprehensive utility classes for collections, strings, I/O, logging, and networking
- Type-safe property access and reflection helpers
- Template-based formatting system
- Custom logging framework wrapping java.util.logging
- SSL/TLS and HTTP utilities

## Build System

This is a Maven project with standard structure:

### Essential Commands
- **Build**: `./mvnw clean install`
- **Test**: `./mvnw test`
- **Run single test**: `./mvnw test -Dtest=ClassName#methodName`
- **Pre-commit checks**: `./mvnw -Ppre-commit clean verify -DskipTests`
- **Clean and verify**: `./mvnw clean verify`

### Project Structure
- Main source: `src/main/java/de/cuioss/tools/`
- Test source: `src/test/java/de/cuioss/tools/`
- Maven module: `de.cuioss.java.tools`
- Current version: 2.4.1-SNAPSHOT

## Architecture

### Core Packages
- `de.cuioss.tools.base` - Basic utilities (Preconditions, BooleanOperations)
- `de.cuioss.tools.collect` - Collection utilities (builders, literals, more collections)
- `de.cuioss.tools.string` - String utilities (Joiner, Splitter, MoreStrings)
- `de.cuioss.tools.io` - I/O utilities (file loaders, path utilities)
- `de.cuioss.tools.logging` - Custom logging framework (CuiLogger)
- `de.cuioss.tools.net` - Network utilities (URL helpers, SSL, HTTP)
- `de.cuioss.tools.lang` - Language utilities (LocaleUtils, MoreObjects)
- `de.cuioss.tools.concurrent` - Concurrency utilities (StopWatch, ConcurrentTools)
- `de.cuioss.tools.formatting` - Template-based formatting system
- `de.cuioss.tools.codec` - Encoding/decoding utilities (Hex)
- `de.cuioss.tools.property` - Property access utilities
- `de.cuioss.tools.reflect` - Reflection helpers

### Design Principles
- Zero external dependencies (except Lombok for development)
- Facade/decorator pattern over complete reimplementation
- Builder patterns for complex object creation
- Immutable objects where possible
- Comprehensive test coverage

## Development Guidelines

### Code Style
- Uses Lombok for reducing boilerplate
- Follows standard Java conventions
- Comprehensive Javadoc documentation
- Package-info.java files for all packages

### Testing
- JUnit 5 with extensive test coverage
- Test support classes in `de.cuioss.tools.support`
- All public APIs must be tested
- Uses Hamcrest for assertions

### Logging
- Custom logging framework in `de.cuioss.tools.logging`
- Uses `CuiLogger` instead of standard logging frameworks
- Formatting supports both `{}` and `%s` placeholders
- Log levels: TRACE, DEBUG, INFO, WARN, ERROR

### Important Notes
- This is a PRE-1.0 project - no backward compatibility guarantees
- Clean APIs aggressively, remove unused code directly
- No deprecation annotations - delete unnecessary code
- Focus on final API design for post-1.0 stability

## Special Considerations

### Module System
- Uses Java modules (`module-info.java`)
- Exports all main packages
- Requires static lombok dependency

### Documentation
- Main documentation in README.adoc
- Detailed package documentation in Javadoc
- Examples in test classes demonstrate usage patterns

### AI Development Rules
- Follow CUI standards as outlined in `doc/ai-rules.md`
- Always run pre-commit checks before making changes
- Use appropriate test coverage for all new code
- Document any new public APIs according to Javadoc standards