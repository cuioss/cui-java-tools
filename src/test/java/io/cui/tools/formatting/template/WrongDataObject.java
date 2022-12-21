package io.cui.tools.formatting.template;

import static io.cui.tools.string.MoreStrings.isEmpty;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.Data;

/**
 * Example implementation of FormatterSupport
 */
@Data
public class WrongDataObject implements FormatterSupport {

    private String firstName;

    private String lastName;

    @Override
    public Map<String, Serializable> getAvailablePropertyValues() {
        Map<String, Serializable> map = new HashMap<>();
        addIfNotNull(map, "firstName", firstName);
        addIfNotNull(map, "lastName", lastName);
        return map;
    }

    @Override
    public List<String> getSupportedPropertyNames() {
        final List<String> result = new ArrayList<>();
        final Field[] fields = this.getClass().getDeclaredFields();
        for (final Field field : fields) {
            result.add(field.getName());
        }
        return result;
    }

    private static void addIfNotNull(final Map<String, Serializable> map, final String key, final String value) {
        if (!isEmpty(value)) {
            map.put(key, value);
        }
    }
}
