/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.property;

import static de.cuioss.tools.property.PropertyHolder.from;
import static de.cuioss.tools.property.PropertyReadWrite.READ_ONLY;
import static de.cuioss.tools.property.PropertyReadWrite.READ_WRITE;
import static de.cuioss.tools.property.PropertyReadWrite.WRITE_ONLY;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Serializable;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.property.support.BeanWithBuilderStyleAccessor;
import de.cuioss.tools.property.support.BeanWithMethodOverload;
import de.cuioss.tools.property.support.BeanWithReadWriteProperties;
import de.cuioss.tools.property.support.ExplodingBean;
import de.cuioss.tools.property.support.GenericTypeWithLowerBoundType;
import de.cuioss.tools.property.support.StringTypedGenericType;
import de.cuioss.tools.support.Generators;

class PropertyHolderTest {

    static final String PROPERTY_NAME = "property";

    @Test
    void shouldResolvePropertyReadWrite() {
        assertEquals(READ_WRITE, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE).get().getReadWrite());
        assertEquals(READ_WRITE,
                from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER).get().getReadWrite());
        assertEquals(READ_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY).get().getReadWrite());
        assertEquals(WRITE_ONLY, from(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY).get().getReadWrite());
        assertFalse(from(BeanWithReadWriteProperties.class, ATTRIBUTE_NOT_ACCESSIBLE).isPresent());
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
        Integer number = Generators.randomInt(0, 1024);
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
        Integer number = Generators.randomInt(0, 1024);
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
        assertThrows(IllegalStateException.class, () -> {
            holder.readFrom(underTest);
        });
        assertThrows(IllegalStateException.class, () -> {
            holder.writeTo(underTest, "");
        });
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
        Integer number = Generators.randomInt(0, 1024);
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
}
