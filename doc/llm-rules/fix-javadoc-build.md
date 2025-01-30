# Fix Javadoc Build Rules

When asked to "fix javadoc build", follow these strict rules:

## 1. Preconditions
Verify all before proceeding:
- Project builds successfully: `./mvnw clean verify`
- No uncommitted changes exist in the repository

## 2. Verify Javadoc Build
Use the appropriate command based on project type:
- Single module projects: `./mvnw clean verify -Pjavadoc`
- Multi-module projects: `./mvnw clean verify -Pjavadoc-mm-reporting`

## 3. Fix Strategy
- Fix ONLY Javadoc errors and warnings from the build
- Do NOT alter or improve documentation content
- Do NOT modify any code
- Make minimal modifications necessary to fix build issues
- Focus only on formatting, references, and tags

## 4. Common Fixes
- Fix invalid {@link} references
- Fix malformed HTML tags
- Fix missing/incorrect parameter documentation
- Fix missing/incorrect return value documentation
- Fix missing/incorrect exception documentation

## 5. Out of Scope
- Documentation improvements
- Code changes
- Content rewrites
- Style changes beyond error fixes

**Note**: These strict rules only apply within the "fix javadoc build" context.
