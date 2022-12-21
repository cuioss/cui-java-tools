package io.cui.tools.formatting.template.lexer;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import io.cui.tools.formatting.template.FormatterSupport;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class NoPublicZeroArgConstructor implements FormatterSupport {


    @Getter
    private final String name;

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        // TODO Auto-generated method stub
        return null;
    }
}

