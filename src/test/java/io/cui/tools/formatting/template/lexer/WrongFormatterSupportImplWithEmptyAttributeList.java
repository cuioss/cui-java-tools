package io.cui.tools.formatting.template.lexer;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.cui.tools.formatting.template.FormatterSupport;

@SuppressWarnings("javadoc")
public class WrongFormatterSupportImplWithEmptyAttributeList implements FormatterSupport {

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        return null;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        final List<String> result = new ArrayList<>();
        result.add(null);
        return result;
    }

}
