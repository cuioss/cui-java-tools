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
package de.cuioss.tools.base;

import lombok.experimental.UtilityClass;

import static de.cuioss.tools.string.MoreStrings.lenientFormat;

/**
 * Static convenience methods that help a method or constructor check whether it was
 * invoked correctly.
 * Similar to guava Preconditions but without dependency.
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava Preconditions</a>
 */
@UtilityClass
public class Preconditions {

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     */
    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression
     * @param message    to be put into the create {@link IllegalArgumentException}
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     */
    public static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression           a boolean expression
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail. The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument. These are matched by position - the
     *                             first {@code %s} gets {@code
     *                             errorMessageArgs[0]} , etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces. Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template. Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalArgumentException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     */
    public static void checkArgument(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalArgumentException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     */
    public static void checkState(boolean expression) {
        if (!expression) {
            throw new IllegalStateException();
        }
    }

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression a boolean expression
     * @param message    to be put into the create {@link IllegalStateException}
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     */
    public static void checkState(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    /**
     * <p>
     * Inspired by Google Guava Preconditions.
     *
     * @param expression           a boolean expression
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail. The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument. These are matched by position - the
     *                             first {@code %s} gets {@code
     *                             errorMessageArgs[0]} , etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces. Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template. Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalStateException if {@code expression} is false
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Preconditions.java">Google Guava</a>
     * </p>
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     */
    public static void checkState(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalStateException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }
}
