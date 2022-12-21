package io.cui.tools.property;

import static io.cui.tools.property.PropertyUtil.readProperty;
import static io.cui.tools.property.PropertyUtil.resolvePropertyType;
import static io.cui.tools.property.PropertyUtil.writeProperty;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_DEFAULT_VALUE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_NOT_ACCESSIBLE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_ONLY;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE_WITH_BUILDER;
import static io.cui.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_WRITE_ONLY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

import io.cui.tools.property.support.BeanForTestingTypeResolving;
import io.cui.tools.property.support.BeanWithMethodOverload;
import io.cui.tools.property.support.BeanWithPrimitives;
import io.cui.tools.property.support.BeanWithReadWriteProperties;
import io.cui.tools.property.support.BeanWithUnusualAttributeCasing;
import io.cui.tools.property.support.ExplodingBean;
import io.cui.tools.support.Generators;
import io.cui.tools.support.StringCaseShuffler;

class PropertyUtilTest {

    static final String PROPERTY_NAME = "property";
    static final String PROPERTY_PRIMITIVE_NAME = "propertyPrimitive";

    @Test
    void shouldReadWriteHappyCase() {
        BeanWithReadWriteProperties underTest = new BeanWithReadWriteProperties();

        assertNull(readProperty(underTest, ATTRIBUTE_READ_WRITE));
        assertNotNull(readProperty(underTest, ATTRIBUTE_DEFAULT_VALUE));

        Integer number = 4;
        assertNotNull(writeProperty(underTest, ATTRIBUTE_READ_WRITE, number));
        assertEquals(number, readProperty(underTest, ATTRIBUTE_READ_WRITE));

        assertNull(readProperty(underTest, ATTRIBUTE_READ_WRITE_WITH_BUILDER));
        assertNotNull(writeProperty(underTest, ATTRIBUTE_READ_WRITE_WITH_BUILDER, number));
        assertEquals(number, readProperty(underTest, ATTRIBUTE_READ_WRITE));

        assertNotNull(writeProperty(underTest, ATTRIBUTE_READ_WRITE, null));
        assertNull(readProperty(underTest, ATTRIBUTE_READ_WRITE));
    }

    @Test
    void shouldHandleOverloadedMethods() {
        BeanWithMethodOverload underTest = new BeanWithMethodOverload();

        assertNull(readProperty(underTest, PROPERTY_NAME));

        Integer number = 4;
        assertNotNull(writeProperty(underTest, PROPERTY_NAME, number));
        assertEquals(number, readProperty(underTest, PROPERTY_NAME));

        assertNotNull(writeProperty(underTest, PROPERTY_NAME, "5"));
        assertEquals(Integer.valueOf(5), readProperty(underTest, PROPERTY_NAME));

        ArrayList<Object> propertyValue = new ArrayList<>();
        assertThrows(IllegalArgumentException.class, () -> {
            writeProperty(underTest, PROPERTY_NAME, propertyValue);
        });
    }

    @Test
    void shouldHandleMethodsWithPrimitives() {
        BeanWithPrimitives underTest = new BeanWithPrimitives();

        assertNull(readProperty(underTest, PROPERTY_NAME));
        assertEquals(0, readProperty(underTest, PROPERTY_PRIMITIVE_NAME));

        Integer number = 4;
        assertNotNull(writeProperty(underTest, PROPERTY_NAME, number));
        assertNotNull(writeProperty(underTest, PROPERTY_PRIMITIVE_NAME, number));
        assertEquals(4, readProperty(underTest, PROPERTY_PRIMITIVE_NAME));

    }

    @Test
    void shouldFailOnInvalidProperty() {
        BeanWithReadWriteProperties underTest = new BeanWithReadWriteProperties();
        assertThrows(IllegalArgumentException.class, () -> {
            readProperty(underTest, ATTRIBUTE_NOT_ACCESSIBLE);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            readProperty(underTest, ATTRIBUTE_WRITE_ONLY);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            writeProperty(underTest, ATTRIBUTE_NOT_ACCESSIBLE, "");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            writeProperty(underTest, ATTRIBUTE_READ_ONLY, "");
        });
    }

    @Test
    void shouldFailOnOnRuntimeExceptionProperty() {
        ExplodingBean underTest = new ExplodingBean();

        underTest.illegalArgumentException();
        assertThrows(IllegalStateException.class, () -> {
            readProperty(underTest, PROPERTY_NAME);
        });
        assertThrows(IllegalStateException.class, () -> {
            writeProperty(underTest, PROPERTY_NAME, "");
        });
    }

    @Test
    void shouldBeFlexibleRegardingCaseSensitivity() {
        BeanWithUnusualAttributeCasing underTest = new BeanWithUnusualAttributeCasing();

        String name = StringCaseShuffler.shuffleCase("url");
        assertNull(readProperty(underTest, name));

        String value = Generators.randomString();
        writeProperty(underTest, name, value);
        assertEquals(value, readProperty(underTest, name));
    }

    @Test
    void shouldResolvePropertyType() {
        assertEquals(Integer.class, resolvePropertyType(BeanForTestingTypeResolving.class, "fieldOnly").get());
        assertEquals(String.class, resolvePropertyType(BeanForTestingTypeResolving.class, "stringProperty").get());
        assertEquals(Float.class, resolvePropertyType(BeanForTestingTypeResolving.class, "floatProperty").get());
        assertFalse(resolvePropertyType(BeanForTestingTypeResolving.class, "notThere").isPresent());
    }

}
