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
import de.cuioss.tools.property.support.*;
import org.junit.jupiter.api.Test;

import java.io.Serializable;

import static de.cuioss.tools.property.PropertyHolder.from;
import static de.cuioss.tools.property.PropertyReadWrite.*;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.*;
import static org.junit.jupiter.api.Assertions.*;

@EnableGeneratorController
class PropertyHolderTest {

    static final String PROPERTY_NAME = "property";

    @Test
    void shouldResolvePropertyReadWrite() {
        assertEquals(READ_WRITE, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get().getReadWrite());
        assertEquals(READ_WRITE,
                from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER).get().getReadWrite());
        assertEquals(READ_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY).get().getReadWrite());
        assertEquals(WRITE_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY).get().getReadWrite());
    }

    @Test
    void shouldResolveFieldWithoutAccessors() {
        var holder = from(BeanWithReadWriteProperties.class, ATTRIBUTE_NOT_ACCESSIBLE);
        assertTrue(holder.isPresent(), "Field without accessors should be resolvable via reflection");
        assertEquals(NONE, holder.get().getReadWrite());
        assertEquals(String.class, holder.get().getType());
        assertEquals(PropertyMemberInfo.DEFAULT, holder.get().getMemberInfo());
    }

    @Test
    void shouldReturnEmptyForNonexistentProperty() {
        assertFalse(from(BeanWithReadWriteProperties.class, "notThereAtAll").isPresent());
    }

    @Test
    void shouldReturnEmptyForIndexedOnlyProperty() {
        assertFalse(from(BeanWithIndexedOnlyProperty.class, "item").isPresent(),
                "Indexed-only property provides no property type and should not be resolvable");
    }

    @Test
    void shouldWriteAndReadPrimitiveProperty() {
        var holder = from(BeanWithPrimitives.class, "propertyPrimitive").get();
        assertEquals(int.class, holder.getType());
        var bean = new BeanWithPrimitives();
        int number = Generators.integers(1, 1024).next();
        assertNotNull(holder.writeTo(bean, number));
        assertEquals(number, holder.readFrom(bean));
    }

    @Test
    void writeToShouldRejectNullForPrimitiveProperty() {
        var holder = from(BeanWithPrimitives.class, "propertyPrimitive").get();
        var bean = new BeanWithPrimitives();
        var exception = assertThrows(IllegalArgumentException.class, () -> holder.writeTo(bean, null));
        assertTrue(exception.getMessage().contains("null"),
                "Message should name 'null' as the provided value: " + exception.getMessage());
    }

    @Test
    void writeToShouldAcceptNullForObjectProperty() {
        var holder = from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get();
        var bean = new BeanWithReadWriteProperties();
        assertNotNull(holder.writeTo(bean, null));
        assertNull(holder.readFrom(bean));
    }

    @Test
    void readFromShouldFailForWriteOnlyProperty() {
        var holder = from(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY).get();
        var bean = new BeanWithReadWriteProperties();
        assertThrows(IllegalStateException.class, () -> holder.readFrom(bean));
    }

    @Test
    void writeToShouldFailForReadOnlyProperty() {
        var holder = from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY).get();
        var bean = new BeanWithReadWriteProperties();
        assertThrows(IllegalStateException.class, () -> holder.writeTo(bean, "value"));
    }

    @Test
    void shouldHandlePropertyMemberInfo() {
        assertEquals(PropertyMemberInfo.DEFAULT,
                from(BeanWithReadWriteProperties.class, BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE).get()
                        .getMemberInfo());
        assertEquals(PropertyMemberInfo.TRANSIENT,
                from(BeanWithReadWriteProperties.class, BeanWithReadWriteProperties.ATTRIBUTE_TRANSIENT_VALUE).get()
                        .getMemberInfo());
    }

    @Test
    void shouldHandleHappyCase() {
        var underTest = from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get();
        assertEquals(READ_WRITE, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(ATTRIBUTE_READ_WRITE, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNotNull(underTest.getReadMethod());
        assertNotNull(underTest.getWriteMethod());
        var bean = new BeanWithReadWriteProperties();
        assertNull(underTest.readFrom(bean));
        Integer number = Generators.integers(0, 1024).next();
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithReadWriteProperties.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
        assertEquals(number, underTest.readFrom(bean));
    }

    @Test
    void shouldHandleBuilderLikeAccess() {
        var underTest = from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER).get();
        assertEquals(READ_WRITE, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(ATTRIBUTE_READ_WRITE_WITH_BUILDER, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNotNull(underTest.getReadMethod());
        assertNotNull(underTest.getWriteMethod());
        var bean = new BeanWithReadWriteProperties();
        assertNull(underTest.readFrom(bean));
        Integer number = Generators.integers(0, 1024).next();
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithReadWriteProperties.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
        assertEquals(number, underTest.readFrom(bean));

    }

    @Test
    void shouldFailOnOnRuntimeExceptionProperty() {
        var underTest = new ExplodingBean();
        var holder = from(ExplodingBean.class, PROPERTY_NAME).get();

        underTest.illegalArgumentException();
        assertThrows(IllegalStateException.class, () ->
                holder.readFrom(underTest));
        assertThrows(IllegalStateException.class, () ->
                holder.writeTo(underTest, ""));
    }

    @Test
    void shouldSupportBuilderLikeAccess() {
        var bean = new BeanWithBuilderStyleAccessor();
        assertTrue(from(BeanWithBuilderStyleAccessor.class, PROPERTY_NAME).isPresent());
        var underTest = from(BeanWithBuilderStyleAccessor.class, PROPERTY_NAME).get();

        assertEquals(WRITE_ONLY, underTest.getReadWrite());
        assertEquals(PropertyMemberInfo.DEFAULT, underTest.getMemberInfo());
        assertEquals(PROPERTY_NAME, underTest.getName());
        assertEquals(Integer.class, underTest.getType());
        assertNull(underTest.getWriteMethod());
        Integer number = Generators.integers(0, 1024).next();
        assertNotNull(underTest.writeTo(bean, number));
        assertEquals(BeanWithBuilderStyleAccessor.class, underTest.writeTo(bean, number).getClass(),
                "Should return initial bean");
    }

    @Test
    void shouldHandleOverloadedMethods() {
        var holder = from(BeanWithMethodOverload.class, PROPERTY_NAME).get();
        assertEquals(Integer.class, holder.getType());
    }

    @Test
    void shouldHandleLowerBoundGenerics() {
        var holder = from(GenericTypeWithLowerBoundType.class, "key").get();
        assertEquals(Serializable.class, holder.getType());
    }

    @Test
    void shouldHandleBoundGenerics() {
        var holder = from(StringTypedGenericType.class, "key").get();
        assertEquals(String.class, holder.getType());
    }

    @Test
    void shouldHandleBuilderStylePropertyEdgeCases() {
        var bean = new BeanWithBuilderStyleAccessor();
        var holder = from(BeanWithBuilderStyleAccessor.class, PROPERTY_NAME).get();

        // Test null value
        assertNotNull(holder.writeTo(bean, null));

        // Test type mismatch
        var wrongType = "not an integer";
        assertThrows(IllegalArgumentException.class, () ->
                        holder.writeTo(bean, wrongType),
                "Should throw IllegalArgumentException for type mismatch");

        // Test null target
        assertThrows(NullPointerException.class, () ->
                        holder.writeTo(null, 42),
                "Should throw NullPointerException for null target");

        // Verify builder chain works
        var result = holder.writeTo(bean, 42);
        assertInstanceOf(BeanWithBuilderStyleAccessor.class, result, "Should return builder instance for chaining");
    }
}
