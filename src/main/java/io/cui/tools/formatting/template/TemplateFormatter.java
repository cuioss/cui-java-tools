package io.cui.tools.formatting.template;

import java.io.Serializable;

/**
 * The formatter should be able to convert complex type based on {@link FormatterSupport} into text
 * by using a defined template.
 *
 * See {@link io.cui.tools.formatting} for details.
 *
 * @param <T> bounded type based on {@link FormatterSupport}
 *
 * @author Eugen Fischer
 */
public interface TemplateFormatter<T extends FormatterSupport> extends Serializable {

    /**
     * Execute transformation based on configured template and values for the defined placeholders.
     * Missing values should get ignored.
     *
     * @param reference must not be {@code null}
     *
     * @return formatted text
     * @throws NullPointerException if reference is missing
     */
    String format(final T reference);

}
