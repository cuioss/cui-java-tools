# Command Configuration

## ./mvnw -Ppre-commit clean install

### Last Execution Duration
- **Duration**: 52000ms (52 seconds)
- **Last Updated**: 2025-10-16

### Acceptable Warnings
- OpenRewrite `CuiLogRecordPatternRecipe` warnings about converting logging to LogRecord pattern
- Deprecation warning for `writeProperty` method in test code (intentional test of deprecated API)

## handle-pull-request

### CI/Sonar Duration
- **Duration**: 300000ms (5 minutes)
- **Last Updated**: 2025-10-16

### Notes
- This duration represents the time to wait for CI and SonarCloud checks to complete
- Includes buffer time for queue delays
