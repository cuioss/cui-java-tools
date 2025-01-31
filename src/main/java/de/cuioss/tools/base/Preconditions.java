/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.base;

import lombok.experimental.UtilityClass;

import static de.cuioss.tools.string.MoreStrings.lenientFormat;

/**
 * Static utility methods for validating method arguments and state. This class
 * provides a lightweight alternative to similar utilities in larger libraries,
 * focusing on common validation scenarios with clear, descriptive error messages.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Argument validation with formatted error messages</li>
 *   <li>State validation for class invariants</li>
 *   <li>Null-safe operation</li>
 *   <li>Support for both simple and complex conditions</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is thread-safe. All methods are stateless and can be safely
 * called from multiple threads concurrently.</p>
 *
 * <h2>Performance Considerations</h2>
 * <ul>
 *   <li>Message formatting is only performed if the validation fails</li>
 *   <li>For best performance, use the simple boolean overloads when no message formatting is needed</li>
 *   <li>String templates are processed using a lightweight formatter</li>
 * </ul>
 *
 * <h2>Error Message Formatting</h2>
 * <p>Error messages support printf-style formatting with {@code %s} placeholders:
 * <ul>
 *   <li>Placeholders are replaced in order with the provided arguments</li>
 *   <li>Extra arguments are appended in square brackets</li>
 *   <li>Missing arguments leave placeholders unchanged</li>
 *   <li>Null arguments are safely converted to "null"</li>
 *   <li>Arrays are properly formatted with their contents</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Basic Argument Validation</h3>
 * <pre>
 * public class UserService {
 *     public void createUser(String username, int age) {
 *         // Simple null check
 *         checkArgument(null != username, "Username must not be null");
 *
 *         // Length validation with formatted message
 *         checkArgument(username.length() &gt;= 3,
 *             "Username must be at least 3 characters long, was: %s", username);
 *
 *         // Range check with multiple parameters
 *         checkArgument(age &gt;= 18 &amp;&amp; age &lt;= 100,
 *             "Age must be between 18 and 100, was: %s", age);
 *     }
 * }
 * </pre>
 *
 * <h3>2. State Validation</h3>
 * <pre>
 * public class ConnectionPool {
 *     private boolean initialized;
 *     private List&lt;Connection&gt; connections;
 *
 *     public Connection getConnection() {
 *         // Verify object state
 *         checkState(initialized, "Connection pool is not initialized");
 *
 *         // Verify resource availability
 *         checkState(!connections.isEmpty(),
 *             "No connections available in pool (size: %s)", connections.size());
 *
 *         return connections.remove(0);
 *     }
 * }
 * </pre>
 *
 * <h3>3. Collection and Array Validation</h3>
 * <pre>
 * public class BatchProcessor {
 *     public void processBatch(List&lt;String&gt; items, String[] config) {
 *         // Check collection
 *         checkArgument(!items.isEmpty(), "Items list must not be empty");
 *
 *         // Check array with index
 *         for (int i = 0; i &lt; items.size(); i++) {
 *             checkArgument(items.get(i) != null,
 *                 "Item at index %s must not be null", i);
 *         }
 *
 *         // Validate array configuration
 *         checkArgument(config.length &gt;= 2,
 *             "Config must have at least 2 elements, had: %s", config.length);
 *     }
 * }
 * </pre>
 *
 * <h3>4. Complex Validations</h3>
 * <pre>
 * public class TransactionService {
 *     public void transfer(Account from, Account to, BigDecimal amount) {
 *         // Multiple conditions in single check
 *         checkArgument(amount != null &amp;&amp; amount.compareTo(BigDecimal.ZERO) &gt; 0,
 *             "Transfer amount must be positive, was: %s", amount);
 *
 *         // Business rule validation
 *         checkState(from.getBalance().compareTo(amount) &gt;= 0,
 *             "Insufficient funds: required %s, available %s",
 *             amount, from.getBalance());
 *
 *         // State consistency check
 *         checkState(!from.isLocked() &amp;&amp; !to.isLocked(),
 *             "Cannot transfer between locked accounts (from: %s, to: %s)",
 *             from.isLocked(), to.isLocked());
 *     }
 * }
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Place validations at the beginning of methods</li>
 *   <li>Use descriptive error messages that include the invalid values</li>
 *   <li>Prefer checkArgument() for parameter validation</li>
 *   <li>Use checkState() for object state validation</li>
 *   <li>Include relevant context in error messages</li>
 *   <li>Group related validations together</li>
 * </ul>
 *
 * <h2>Exception Handling</h2>
 * <ul>
 *   <li>checkArgument() throws IllegalArgumentException</li>
 *   <li>checkState() throws IllegalStateException</li>
 *   <li>All exceptions include the formatted error message</li>
 *   <li>Error messages support printf-style formatting with %s</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava Preconditions</a>
 * @since 1.0
 */
@UtilityClass
public class Preconditions {

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     * Inspired by Google Guava Preconditions.
     *
     * <p>This is the most basic form of argument validation, throwing an exception
     * with no message. For better error reporting, use the overloads that accept
     * a message template.</p>
     *
     * @param expression a boolean expression that should evaluate to true for valid arguments
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     * Inspired by Google Guava Preconditions.
     *
     * <p>This overload accepts a simple message string that will be used as-is
     * in the exception if the check fails. For message formatting, use the
     * template-based overload instead.</p>
     *
     * @param expression a boolean expression that should evaluate to true for valid arguments
     * @param message    to be put into the created {@link IllegalArgumentException}.
     *                   May be null, in which case no message will be included.
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method. Inspired by Google Guava Preconditions.
     *
     * <p>This overload supports message formatting with printf-style placeholders.
     * The message is only formatted if the check fails, making it efficient for
     * frequently called validations.</p>
     *
     * <p><b>Message Formatting Examples:</b></p>
     * <pre>
     * // Basic placeholder replacement
     * checkArgument(age &gt;= 18, "Age must be at least 18, was: %s", age);
     *
     * // Multiple placeholders
     * checkArgument(end &gt; start, "Invalid range: %s to %s", start, end);
     *
     * // Array formatting
     * checkArgument(array.length &gt; 0, "Array must not be empty: %s", array);
     *
     * // Null handling
     * checkArgument(value != null, "Value required, got: %s", value); // prints "null"
     * </pre>
     *
     * @param expression           a boolean expression that should evaluate to true for valid arguments
     * @param errorMessageTemplate a template for the exception message should the
     *                            check fail. The message is formed by replacing
     *                            each {@code %s} placeholder in the template with
     *                            an argument. These are matched by position - the
     *                            first {@code %s} gets {@code
     *                            errorMessageArgs[0]}, etc. Unmatched arguments will be appended to
     *                            the formatted message in square braces.
     *                            Unmatched
     *                            placeholders will be left as-is. May be null.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                            template. Arguments are converted to strings
     *                            using {@link String#valueOf(Object)}. May be null
     *                            or empty, but elements may not be null.
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkArgument(boolean expression, String errorMessageTemplate,
            Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalArgumentException(
                    lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     * Inspired by Google Guava Preconditions.
     *
     * <p>This is the most basic form of state validation, throwing an exception
     * with no message. For better error reporting, use the overloads that accept
     * a message template.</p>
     *
     * @param expression a boolean expression that should evaluate to true for valid state
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkState(boolean expression) {
        if (!expression) {
            throw new IllegalStateException();
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     * Inspired by Google Guava Preconditions.
     *
     * <p>This overload accepts a simple message string that will be used as-is
     * in the exception if the check fails. For message formatting, use the
     * template-based overload instead.</p>
     *
     * @param expression a boolean expression that should evaluate to true for valid state
     * @param message    to be put into the created {@link IllegalStateException}.
     *                   May be null, in which case no message will be included.
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkState(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     * Inspired by Google Guava Preconditions.
     *
     * <p>This overload supports message formatting with printf-style placeholders.
     * The message is only formatted if the check fails, making it efficient for
     * frequently called validations.</p>
     *
     * <p><b>Message Formatting Examples:</b></p>
     * <pre>
     * // Basic placeholder replacement
     * checkState(isInitialized(), "Service not initialized, status: %s", status);
     *
     * // Multiple placeholders
     * checkState(connection.isValid(), "Invalid connection: host=%s, port=%s", host, port);
     *
     * // Collection state
     * checkState(!items.isEmpty(), "No items available (capacity: %s)", items.size());
     *
     * // Complex state
     * checkState(cache.isLoaded() &amp;&amp; cache.isValid(),
     *           "Cache in invalid state: loaded=%s, valid=%s",
     *           cache.isLoaded(), cache.isValid());
     * </pre>
     *
     * @param expression           a boolean expression that should evaluate to true for valid state
     * @param errorMessageTemplate a template for the exception message should the
     *                            check fail. The message is formed by replacing
     *                            each {@code %s} placeholder in the template with
     *                            an argument. These are matched by position - the
     *                            first {@code %s} gets {@code errorMessageArgs[0]},
     *                            etc. Unmatched arguments will be appended to
     *                            the formatted message in square braces. Unmatched
     *                            placeholders will be left as-is. May be null.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                            template. Arguments are converted to strings
     *                            using {@link String#valueOf(Object)}. May be null
     *                            or empty, but elements may not be null.
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * @since 1.0
     */
    public static void checkState(boolean expression, String errorMessageTemplate,
            Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalStateException(
                    lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }
}
