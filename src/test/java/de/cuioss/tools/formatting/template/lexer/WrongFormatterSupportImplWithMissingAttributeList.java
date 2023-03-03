package de.cuioss.tools.formatting.template.lexer;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import de.cuioss.tools.formatting.template.FormatterSupport;

@SuppressWarnings("javadoc")
public class WrongFormatterSupportImplWithMissingAttributeList implements FormatterSupport {

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        return null;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        return null;
    }

}
