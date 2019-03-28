package de.icw.util.formatting.template;

import java.io.Serializable;

/**
 * Formatter which is able to replace parameter inside the template based on
 * {@link FormatterSupport} information. See {@link de.icw.util.formatting} for details.
 *
 * @author Eugen Fischer
 * @param <T>
 */
public interface TemplateFormatter<T extends FormatterSupport> extends Serializable {

    /**
     * replace attributes from template by attribute values from the map.
     * missing template attributes will be ignored and doesn't add to result at
     * all.
     *
     * @param reference
     *            must not be null
     * @return completed template
     */
    String format(final T reference);

}
