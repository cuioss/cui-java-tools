/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.logging;

import java.util.function.Supplier;

/**
 * Provides a structured approach to logging in the CUI ecosystem, focusing on consistent
 * log message formatting and identification.
 *
 * <h2>Key Concepts</h2>
 * <ul>
 *   <li><b>Prefix</b>: A short identifier for the subsystem (e.g., 'CUI', 'AUTH')</li>
 *   <li><b>Identifier</b>: A numeric code uniquely identifying the log message type</li>
 *   <li><b>Message Template</b>: The message pattern with placeholders for variables</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Basic Usage with LogRecordModel</h3>
 * <pre>
 * LogRecord loginRecord = LogRecordModel.builder()
 *     .prefix("AUTH")
 *     .identifier(1001)
 *     .message("User login attempt: {}")
 *     .build();
 *
 * // Outputs: AUTH-1001: User login attempt: john.doe
 * logger.info(loginRecord.format("john.doe"));
 * </pre>
 *
 * <h3>2. Using with Exception Handling</h3>
 * <pre>
 * LogRecord errorRecord = LogRecordModel.builder()
 *     .prefix("CUI")
 *     .identifier(5001)
 *     .message("Operation failed: %s")
 *     .build();
 *
 * try {
 *     // ... some operation
 * } catch (Exception e) {
 *     // Outputs: CUI-5001: Operation failed: Invalid input
 *     logger.error(errorRecord.format(e.getMessage()));
 * }
 * </pre>
 *
 * <h3>3. Using with Suppliers for Lazy Evaluation</h3>
 * <pre>
 * LogRecord perfRecord = LogRecordModel.builder()
 *     .prefix("PERF")
 *     .identifier(2001)
 *     .message("Operation completed in {} ms")
 *     .build();
 *
 * // Message will only be formatted if debug is enabled
 * logger.debug(() -> perfRecord.format(stopWatch.getTime()));
 * </pre>
 *
 * <h3>4. Combining with CuiLogger</h3>
 * <pre>
 * private static final CuiLogger log = new CuiLogger(MyClass.class);
 * private static final LogRecord CONFIG_CHANGE = LogRecordModel.builder()
 *     .prefix("CONFIG")
 *     .identifier(3001)
 *     .message("Configuration changed - key: {}, old: {}, new: {}")
 *     .build();
 *
 * public void updateConfig(String key, String oldValue, String newValue) {
 *     // Outputs: CONFIG-3001: Configuration changed - key: timeout, old: 1000, new: 2000
 *     log.info(CONFIG_CHANGE.format(key, oldValue, newValue));
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Define LogRecord instances as static final constants for reuse</li>
 *   <li>Use meaningful prefixes that identify the subsystem</li>
 *   <li>Use consistent identifier ranges for different types of messages</li>
 *   <li>Document the meaning of each identifier in a central location</li>
 *   <li>Use suppliers for expensive message construction</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see LogRecordModel
 * @see CuiLogger
 */
public interface LogRecord {

    /**
     * @return the prefix for identifying the log-entry, e.g. 'CUI'
     */
    String getPrefix();

    /**
     * @return the identifier for the concrete entry, e.g. '100'
     */
    Integer getIdentifier();

    /**
     * @return The message template for creating the log-message
     */
    String getTemplate();

    /**
     * Returns a {@link Supplier} view on the formatter
     *
     * @param parameter optional, used for filling the template
     * @return a {@link Supplier} view on the formatter
     */
    Supplier<String> supplier(Object... parameter);

    /**
     * Formats the template with the given object. <em>Important:</em> it implicitly
     * prepends the identifier, e.g. "CUI-100: " in front of the created message.
     *
     * @param parameter optional, used for filling the template
     * @return the formated String.
     */
    String format(Object... parameter);

    /**
     * @return the concatenated identifier String, e.g. CUI-100
     */
    String resolveIdentifierString();

}
