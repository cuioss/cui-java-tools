package de.cuioss.tools.formatting.template;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Provides runtime-information about a bean without resorting to reflection.
 *
 * @author Eugen Fischer
 */
public interface FormatterSupport {

    /**
     * Allow easier access to available properties.
     * Order of available properties and their values has no effect.
     *
     * @return Map<String, Serializable> of property name -> property Value for <b>non</b>
     *         {@code null}
     *         properties
     */
    Map<String, Serializable> getAvailablePropertyValues();

    /**
     * @return list of all supported properties
     */
    List<String> getSupportedPropertyNames();

}
