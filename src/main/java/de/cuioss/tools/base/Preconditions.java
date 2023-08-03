package de.cuioss.tools.base;

import static de.cuioss.tools.string.MoreStrings.lenientFormat;

import lombok.experimental.UtilityClass;

/**
 * Inspired by com.google.common.base.Preconditions. Defines a subset of the
 * corresponding Preconditions
 *
 * @author com.google.common.base.Preconditions
 * @author Oliver Wolff
 *
 */
@UtilityClass
public class Preconditions {

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     *
     * @param expression a boolean expression
     * @throws IllegalArgumentException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     *
     * @param expression a boolean expression
     * @param message    to be put into the create {@link IllegalArgumentException}
     * @throws IllegalArgumentException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     *
     * @param expression           a boolean expression
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail. The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument. These are matched by position - the
     *                             first {@code %s} gets {@code
     *     errorMessageArgs[0]} , etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces. Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template. Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalArgumentException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkArgument(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalArgumentException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     *
     * @param expression a boolean expression
     * @throws IllegalStateException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkState(boolean expression) {
        if (!expression) {
            throw new IllegalStateException();
        }
    }

    /**
     * Ensures the truth of an expression involving the state of the calling
     * instance, but not involving any parameters to the calling method.
     *
     * @param expression a boolean expression
     * @param message    to be put into the create {@link IllegalStateException}
     * @throws IllegalStateException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkState(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    /**
     * Ensures the truth of an expression involving one or more parameters to the
     * calling method.
     *
     * @param expression           a boolean expression
     * @param errorMessageTemplate a template for the exception message should the
     *                             check fail. The message is formed by replacing
     *                             each {@code %s} placeholder in the template with
     *                             an argument. These are matched by position - the
     *                             first {@code %s} gets {@code
     *     errorMessageArgs[0]} , etc. Unmatched arguments will be appended to
     *                             the formatted message in square braces. Unmatched
     *                             placeholders will be left as-is.
     * @param errorMessageArgs     the arguments to be substituted into the message
     *                             template. Arguments are converted to strings
     *                             using {@link String#valueOf(Object)}.
     * @throws IllegalStateException if {@code expression} is false
     * @author com.google.common.base.Preconditions
     */
    public static void checkState(boolean expression, String errorMessageTemplate, Object... errorMessageArgs) {
        if (!expression) {
            throw new IllegalStateException(lenientFormat(errorMessageTemplate, errorMessageArgs));
        }
    }
}
