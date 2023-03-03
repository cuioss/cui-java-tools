package de.cuioss.tools.property;

import static de.cuioss.tools.property.PropertyUtil.readProperty;
import static de.cuioss.tools.property.PropertyUtil.resolvePropertyType;
import static de.cuioss.tools.property.PropertyUtil.writeProperty;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_DEFAULT_VALUE;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_NOT_ACCESSIBLE;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_ONLY;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE_WITH_BUILDER;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_WRITE_ONLY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.property.support.BeanForTestingTypeResolving;
import de.cuioss.tools.property.support.BeanWithMethodOverload;
import de.cuioss.tools.property.support.BeanWithPrimitives;
import de.cuioss.tools.property.support.BeanWithReadWriteProperties;
import de.cuioss.tools.property.support.BeanWithUnusualAttributeCasing;
import de.cuioss.tools.property.support.ExplodingBean;
import de.cuioss.tools.support.Generators;
import de.cuioss.tools.support.StringCaseShuffler;

class PropertyUtilTest {

    static final String PROPERTY_NAME = "property";
    static final String PROPERTY_PRIMITIVE_NAME = "propertyPrimitive";

    @Test
    void shouldReadWriteHappyCase() {
        var underTest = new BeanWithReadWriteProperties();

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
        var underTest = new BeanWithMethodOverload();

        assertNull(readProperty(underTest, PROPERTY_NAME));

        Integer number = 4;
        assertNotNull(writeProperty(underTest, PROPERTY_NAME, number));
        assertEquals(number, readProperty(underTest, PROPERTY_NAME));

        assertNotNull(writeProperty(underTest, PROPERTY_NAME, "5"));
        assertEquals(Integer.valueOf(5), readProperty(underTest, PROPERTY_NAME));

        var propertyValue = new ArrayList<>();
        assertThrows(IllegalArgumentException.class, () -> {
            writeProperty(underTest, PROPERTY_NAME, propertyValue);
        });
    }

    @Test
    void shouldHandleMethodsWithPrimitives() {
        var underTest = new BeanWithPrimitives();

        assertNull(readProperty(underTest, PROPERTY_NAME));
        assertEquals(0, readProperty(underTest, PROPERTY_PRIMITIVE_NAME));

        Integer number = 4;
        assertNotNull(writeProperty(underTest, PROPERTY_NAME, number));
        assertNotNull(writeProperty(underTest, PROPERTY_PRIMITIVE_NAME, number));
        assertEquals(4, readProperty(underTest, PROPERTY_PRIMITIVE_NAME));

    }

    @Test
    void shouldFailOnInvalidProperty() {
        var underTest = new BeanWithReadWriteProperties();
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
        var underTest = new ExplodingBean();

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
        var underTest = new BeanWithUnusualAttributeCasing();

        var name = StringCaseShuffler.shuffleCase("url");
        assertNull(readProperty(underTest, name));

        var value = Generators.randomString();
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
