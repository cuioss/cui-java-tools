/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.logging;

import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.util.function.Supplier;

import static de.cuioss.tools.string.MoreStrings.lenientFormat;
import static de.cuioss.tools.string.MoreStrings.nullToEmpty;

/**
 * Implementation of {@link LogRecord} that provides a builder-based approach to creating
 * structured log messages. This class is designed to enforce consistent logging patterns
 * across the application.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Builder pattern for easy instantiation</li>
 *   <li>Support for both '%s' and '{}' placeholders</li>
 *   <li>Automatic prefix prepending</li>
 *   <li>Thread-safe immutable implementation</li>
 *   <li>Null-safe operation</li>
 * </ul>
 *
 * <h2>Implementation Examples</h2>
 *
 * <h3>1. Creating Common Log Messages</h3>
 * <pre>{@code
 * public class UserService {
 *     private static final LogRecord USER_CREATED = LogRecordModel.builder()
 *         .prefix("USER")
 *         .identifier(1001)
 *         .message("New user created - Username: {}, Roles: {}")
 *         .build();
 *
 *     private static final LogRecord LOGIN_FAILED = LogRecordModel.builder()
 *         .prefix("AUTH")
 *         .identifier(1002)
 *         .message("Login failed - Username: {}, Reason: {}")
 *         .build();
 *
 *     private final CuiLogger log = new CuiLogger(UserService.class);
 *
 *     public void createUser(String username, Set<String> roles) {
 *         // Will output: USER-1001: New user created - Username: john.doe, Roles: [ADMIN, USER]
 *         log.info(USER_CREATED.format(username, roles));
 *     }
 *
 *     public void handleLoginFailure(String username, String reason) {
 *         // Will output: AUTH-1002: Login failed - Username: john.doe, Reason: Invalid password
 *         log.warn(LOGIN_FAILED.format(username, reason));
 *     }
 * }
 * }</pre>
 *
 * <h3>2. Mixed Placeholder Styles</h3>
 * <pre>{@code
 * // Both styles work and can be mixed
 * LogRecord mixed = LogRecordModel.builder()
 *     .prefix("APP")
 *     .identifier(2001)
 *     .message("Process {} completed with status %s")  // Both {} and %s work
 *     .build();
 *
 * // Outputs: APP-2001: Process backup completed with status SUCCESS
 * logger.info(mixed.format("backup", "SUCCESS"));
 * }</pre>
 *
 * <h3>3. Error Handling Pattern</h3>
 * <pre>{@code
 * public class DataService {
 *     private static final LogRecord OPERATION_FAILED = LogRecordModel.builder()
 *         .prefix("DATA")
 *         .identifier(5001)
 *         .message("Operation '{}' failed - Details: %s")
 *         .build();
 *
 *     private final CuiLogger log = new CuiLogger(DataService.class);
 *
 *     public void performOperation(String name) {
 *         try {
 *             // ... operation code
 *         } catch (Exception e) {
 *             // Will output: DATA-5001: Operation 'data-sync' failed - Details: Connection timeout
 *             log.error(OPERATION_FAILED.format(name, e.getMessage()));
 *             throw new ServiceException("Operation failed", e);
 *         }
 *     }
 * }
 * }</pre>
 *
 * <h3>4. Performance Logging Pattern</h3>
 * <pre>{@code
 * public class PerformanceMonitor {
 *     private static final LogRecord EXECUTION_TIME = LogRecordModel.builder()
 *         .prefix("PERF")
 *         .identifier(2001)
 *         .message("Method '{}' executed in {} ms [Thread: {}]")
 *         .build();
 *
 *     private final CuiLogger log = new CuiLogger(PerformanceMonitor.class);
 *
 *     public void logExecutionTime(String methodName, long timeMs) {
 *         if (log.isDebugEnabled()) {
 *             String threadName = Thread.currentThread().getName();
 *             // Will output: PERF-2001: Method 'processData' executed in 150 ms [Thread: main]
 *             log.debug(EXECUTION_TIME.format(methodName, timeMs, threadName));
 *         }
 *     }
 * }
 * }</pre>
 *
 * <h2>Implementation Notes</h2>
 * <ul>
 *   <li>The class is immutable and thread-safe</li>
 *   <li>All builder parameters are validated for null</li>
 *   <li>Message formatting is done lazily on format() call</li>
 *   <li>Prefix is always prepended to the formatted message</li>
 *   <li>The format uses {@link de.cuioss.tools.string.MoreStrings#lenientFormat}</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see LogRecord
 * @see CuiLogger
 * @see de.cuioss.tools.string.MoreStrings#lenientFormat
 */
public class LogRecordModel implements LogRecord {

    private static final String PREFIX_IDENTIFIER_TEMPLATE = "%s-%s";
    private static final String AFTER_PREFIX = ": ";

    @Getter
    @NonNull
    private final String prefix;

    @Getter
    @NonNull
    private final Integer identifier;

    @Getter
    @NonNull
    private final String template;

    /** Tiniest of optimization. Needs to be verified. */
    private String parsedMessageTemplate;
    private String parsedIdentifier;

    protected String getParsedMessageTemplate() {
        if (null == parsedMessageTemplate) {
            parsedMessageTemplate = CuiLogger.SLF4J_PATTERN.matcher(nullToEmpty(getTemplate())).replaceAll("%s");
        }
        return parsedMessageTemplate;
    }

    @Override
    public String format(Object... parameter) {
        return resolveIdentifierString() + AFTER_PREFIX +
                lenientFormat(getParsedMessageTemplate(), parameter);
    }

    @Override
    public Supplier<String> supplier(Object... parameter) {
        return () -> format(parameter);
    }

    @Override
    public String resolveIdentifierString() {
        if (null == parsedIdentifier) {
            parsedIdentifier = String.format(PREFIX_IDENTIFIER_TEMPLATE, getPrefix(), getIdentifier());
        }
        return parsedIdentifier;
    }

    @Builder
    private LogRecordModel(@NonNull String prefix, @NonNull Integer identifier, @NonNull String template) {
        this.prefix = prefix;
        this.identifier = identifier;
        this.template = template;
    }

}
