/**
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

import de.cuioss.tools.property.support.BeanWithReadWriteProperties;
import org.junit.jupiter.api.Test;

import java.beans.IntrospectionException;
import java.beans.Introspector;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static de.cuioss.tools.property.PropertyReadWrite.NONE;
import static de.cuioss.tools.property.PropertyReadWrite.READ_ONLY;
import static de.cuioss.tools.property.PropertyReadWrite.READ_WRITE;
import static de.cuioss.tools.property.PropertyReadWrite.WRITE_ONLY;
import static de.cuioss.tools.property.PropertyReadWrite.fromPropertyDescriptor;
import static de.cuioss.tools.property.PropertyReadWrite.resolveForBean;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_NOT_ACCESSIBLE;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_ONLY;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_READ_WRITE_WITH_BUILDER;
import static de.cuioss.tools.property.support.BeanWithReadWriteProperties.ATTRIBUTE_WRITE_ONLY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PropertyReadWriteTest {

    @Test
    void shouldResolveReflectionBases() {
        assertEquals(READ_WRITE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE));
        assertEquals(READ_WRITE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER));
        assertEquals(READ_ONLY, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY));
        assertEquals(WRITE_ONLY, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY));
        assertEquals(NONE, resolveForBean(BeanWithReadWriteProperties.class, ATTRIBUTE_NOT_ACCESSIBLE));
    }

    @Test
    void shouldResolvePropertyDescriptor() throws IntrospectionException {
        assertEquals(READ_WRITE,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE));
        assertEquals(READ_WRITE,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_WRITE_WITH_BUILDER));
        assertEquals(READ_ONLY, resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_READ_ONLY));
        assertEquals(WRITE_ONLY,
                resolveWithPropertyDescriptor(BeanWithReadWriteProperties.class, ATTRIBUTE_WRITE_ONLY));
    }

    private PropertyReadWrite resolveWithPropertyDescriptor(Class<?> type, String attributeName)
            throws IntrospectionException {
        var info = Introspector.getBeanInfo(type);
        var descriptor = mutableList(info.getPropertyDescriptors()).stream()
                .filter(desc -> attributeName.equalsIgnoreCase(desc.getName())).findFirst();
        assertTrue(descriptor.isPresent());

        return fromPropertyDescriptor(descriptor.get(), type, attributeName);
    }

    @Test
    void shouldPovideCorrectData() {
        assertTrue(READ_ONLY.isReadable());
        assertFalse(READ_ONLY.isWriteable());

        assertFalse(WRITE_ONLY.isReadable());
        assertTrue(WRITE_ONLY.isWriteable());

        assertTrue(READ_WRITE.isReadable());
        assertTrue(WRITE_ONLY.isWriteable());

        assertFalse(NONE.isReadable());
        assertFalse(NONE.isWriteable());
    }

}
