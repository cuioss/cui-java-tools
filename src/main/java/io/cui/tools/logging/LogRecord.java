
package io.cui.tools.logging;

import java.util.function.Supplier;

/**
 * Provides additional information for simplifying logging
 *
 * @author Oliver Wolff
 *
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
     * Formats the template with the given object. <em>Important:</em> it implicitly prepends the
     * identifier, e.g. "CUI-100: " in front of the created message.
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
