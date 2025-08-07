/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.property;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.tools.property.support.BeanForTestingTypeResolving;
import de.cuioss.tools.property.support.BeanWithMethodOverload;
import de.cuioss.tools.property.support.BeanWithPrimitives;
import de.cuioss.tools.property.support.BeanWithReadWriteProperties;
import de.cuioss.tools.property.support.BeanWithUnusualAttributeCasing;
import de.cuioss.tools.property.support.ExplodingBean;
import de.cuioss.tools.support.StringCaseShuffler;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static de.cuioss.tools.property.PropertyUtil.*;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.*;
import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings({"java:S5738"})
@EnableGeneratorController
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
        assertEquals(5, readProperty(underTest, PROPERTY_NAME));

        var propertyValue = new ArrayList<>();
        assertThrows(IllegalArgumentException.class, () ->
                writeProperty(underTest, PROPERTY_NAME, propertyValue));
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
        assertThrows(IllegalArgumentException.class, () ->
                readProperty(underTest, ATTRIBUTE_NOT_ACCESSIBLE));
        assertThrows(IllegalArgumentException.class, () ->
                readProperty(underTest, ATTRIBUTE_WRITE_ONLY));
        assertThrows(IllegalArgumentException.class, () ->
                writeProperty(underTest, ATTRIBUTE_NOT_ACCESSIBLE, ""));
        assertThrows(IllegalArgumentException.class, () ->
                writeProperty(underTest, ATTRIBUTE_READ_ONLY, ""));
    }

    @Test
    void shouldFailOnOnRuntimeExceptionProperty() {
        var underTest = new ExplodingBean();

        underTest.illegalArgumentException();
        assertThrows(IllegalStateException.class, () ->
                readProperty(underTest, PROPERTY_NAME));
        assertThrows(IllegalStateException.class, () ->
                writeProperty(underTest, PROPERTY_NAME, ""));
    }

    @Test
    void shouldBeFlexibleRegardingCaseSensitivity() {
        var underTest = new BeanWithUnusualAttributeCasing();

        var name = StringCaseShuffler.shuffleCase("url");
        assertNull(readProperty(underTest, name));

        var value = Generators.nonEmptyStrings().next();
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
