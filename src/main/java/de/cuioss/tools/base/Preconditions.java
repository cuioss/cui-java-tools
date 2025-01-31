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
 *         checkArgument(username.length() >= 3,
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
 *         checkArgument(config.length >= 2,
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
 *         checkState(from.getBalance().compareTo(amount) >= 0,
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
 */
@UtilityClass
public class Preconditions {

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression that should evaluate to true for valid arguments
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
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
     * @param expression a boolean expression that should evaluate to true for valid arguments
     * @param message    to be put into the created {@link IllegalArgumentException}
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
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
     * @param expression           a boolean expression that should evaluate to true for valid arguments
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail.
     *                             The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument.
     *                             These are matched by position - the
     *                             first {@code %s} gets {@code
     *                             errorMessageArgs[0]}, etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces.
     *                             Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template.
     *                             Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     */
    public static void checkArgument(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalArgumentException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression that should evaluate to true for valid state
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
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
     * @param expression a boolean expression that should evaluate to true for valid state
     * @param message    to be put into the created {@link IllegalStateException}
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
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
     * @param expression           a boolean expression that should evaluate to true for valid state
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail.
     *                             The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument.
     *                             These are matched by position - the
     *                             first {@code %s} gets {@code
     *                             errorMessageArgs[0]}, etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces.
     *                             Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template.
     *                             Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     */
    public static void checkState(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalStateException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }
}
