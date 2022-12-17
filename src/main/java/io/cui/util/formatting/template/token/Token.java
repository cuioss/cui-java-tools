package io.cui.util.formatting.template.token;

import java.io.Serializable;

import io.cui.util.formatting.template.FormatterSupport;

/**
 * Any token should provide a method to substitute "placeholder" with his value
 *
 * @author Eugen Fischer
 */
public interface Token extends Serializable {

    /**
     * @param content must not be null
     * @return token specific template with substituted attribute value if attribute exists,
     *         <code>empty</code> String otherwise
     */
    String substituteAttribute(FormatterSupport content);

    /**
     * @return true if Token has no substitutions
     */
    boolean isStringToken();

}
