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
package de.cuioss.tools.reflect;

import de.cuioss.tools.property.support.BeanWithUnusualAttributeCasing;
import de.cuioss.tools.reflect.support.ChildAnnotatedClass;
import de.cuioss.tools.reflect.support.FieldNameClass;
import de.cuioss.tools.reflect.support.MethodNameClass;
import de.cuioss.tools.reflect.support.NestedGenericBaseClass;
import de.cuioss.tools.reflect.support.NestedGenericSample;
import de.cuioss.tools.reflect.support.NotAnnotatedClass;
import de.cuioss.tools.reflect.support.StringTypedArrayList;
import de.cuioss.tools.support.StringCaseShuffler;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("deprecation")
class MoreReflectionTest {

    @Test
    void shouldHandleAttributeName() {
        assertEquals("name", MoreReflection.computePropertyNameFromMethodName("setName"));
        assertEquals("name", MoreReflection.computePropertyNameFromMethodName("getName"));
        assertEquals("name", MoreReflection.computePropertyNameFromMethodName("isName"));
        assertEquals("iName", MoreReflection.computePropertyNameFromMethodName("iName"));
        assertEquals("is", MoreReflection.computePropertyNameFromMethodName("is"));
        assertEquals("a", MoreReflection.computePropertyNameFromMethodName("isA"));
        assertEquals("a", MoreReflection.computePropertyNameFromMethodName("getA"));
        assertEquals("a", MoreReflection.computePropertyNameFromMethodName("setA"));
        assertEquals("get", MoreReflection.computePropertyNameFromMethodName("get"));
        assertEquals("set", MoreReflection.computePropertyNameFromMethodName("set"));
        assertEquals("setName", MoreReflection.computePropertyNameFromMethodName("setSetName"));
    }

    @Test
    void shouldAccessGetterMethods() {
        assertTrue(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "name").isPresent());
        assertTrue(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "flag").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "protected").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "private").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "module").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "static").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "wrongName").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "class").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameClass.class, "wrongParameter").isPresent());
    }

    @Test
    void shouldFilterAccessGetterMethods() {
        assertEquals(3, MoreReflection.retrieveAccessMethods(MethodNameClass.class, Collections.emptyList()).size());
        assertEquals(2, MoreReflection.retrieveAccessMethods(MethodNameClass.class, mutableList("name")).size());
    }

    @Test
    void shouldDetectAccessMethodsCaseInsensitively() {
        var propertyName = StringCaseShuffler.shuffleCase("url");
        assertTrue(MoreReflection.retrieveAccessMethod(BeanWithUnusualAttributeCasing.class, propertyName).isPresent(),
                "Looked for " + propertyName);
    }

    @Test
    void shouldAccessSingleModifierMethods() {
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "name", String.class).isPresent());
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "flag", boolean.class).isPresent());
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "flagObject", Boolean.class).isPresent());

        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "builderWriteMethod", String.class)
                .isPresent());

        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "name", boolean.class).isPresent());
        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "wrongParameterCount", String.class)
                .isPresent());
    }

    @Test
    void shouldDetectModifierMethodsCaseInsensitively() {
        var propertyName = StringCaseShuffler.shuffleCase("url");
        assertTrue(MoreReflection.retrieveWriteMethod(BeanWithUnusualAttributeCasing.class, propertyName, String.class)
                .isPresent(), "Looked for " + propertyName);
    }

    @Test
    void shouldAccessSingleModifierMethodsWithAutoboxing() {
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "flag", Boolean.class).isPresent());
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "flagObject", boolean.class).isPresent());
    }

    @Test
    void shouldAccessPossibleModifierMethods() {
        assertEquals(1, MoreReflection.retrieveWriteMethodCandidates(MethodNameClass.class, "name").size());
        assertEquals(1, MoreReflection.retrieveWriteMethodCandidates(MethodNameClass.class, "flag").size());
        assertEquals(1,
                MoreReflection.retrieveWriteMethodCandidates(MethodNameClass.class, "builderWriteMethod").size());

        assertEquals(0, MoreReflection.retrieveWriteMethodCandidates(MethodNameClass.class, "notThere").size());

        assertEquals(0,
                MoreReflection.retrieveWriteMethodCandidates(MethodNameClass.class, "wrongParameterCount").size());

    }

    @Test
    void shouldConvertPrimitiveToWrapperType() {
        assertEquals(Boolean.class, MoreReflection.resolveWrapperTypeForPrimitive(boolean.class));
        assertEquals(Byte.class, MoreReflection.resolveWrapperTypeForPrimitive(byte.class));
        assertEquals(Character.class, MoreReflection.resolveWrapperTypeForPrimitive(char.class));
        assertEquals(Short.class, MoreReflection.resolveWrapperTypeForPrimitive(short.class));
        assertEquals(Integer.class, MoreReflection.resolveWrapperTypeForPrimitive(int.class));
        assertEquals(Long.class, MoreReflection.resolveWrapperTypeForPrimitive(long.class));
        assertEquals(Float.class, MoreReflection.resolveWrapperTypeForPrimitive(float.class));
        assertEquals(Double.class, MoreReflection.resolveWrapperTypeForPrimitive(double.class));
        // No Primitive KeyStoreType
        assertEquals(Collection.class, MoreReflection.resolveWrapperTypeForPrimitive(Collection.class));
        assertEquals(Void.class, MoreReflection.resolveWrapperTypeForPrimitive(Void.class));
    }

    @Test
    void shouldExtractAllAnnotations() {
        assertTrue(MoreReflection.extractAllAnnotations(null, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(NotAnnotatedClass.class, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(Object.class, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(List.class, Resource.class).isEmpty());

        assertEquals(1, MoreReflection.extractAllAnnotations(ChildAnnotatedClass.class, Deprecated.class).size());
        assertEquals(2, MoreReflection.extractAllAnnotations(ChildAnnotatedClass.class, Resource.class).size());

    }

    @Test
    void shouldExtractSingleAnnotations() {
        assertFalse(MoreReflection.extractAnnotation(null, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(NotAnnotatedClass.class, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(Object.class, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(List.class, Resource.class).isPresent());

        assertTrue(MoreReflection.extractAnnotation(ChildAnnotatedClass.class, Deprecated.class).isPresent());
        assertTrue(MoreReflection.extractAnnotation(ChildAnnotatedClass.class, Resource.class).isPresent());

    }

    @Test
    void shouldAccessField() {
        assertTrue(MoreReflection.accessField(FieldNameClass.class, "myField").isPresent());
        assertFalse(MoreReflection.accessField(FieldNameClass.class, "notThere").isPresent());
        // read from parent
        assertTrue(MoreReflection.accessField(FieldNameClass.class, "flag").isPresent());
        // should be cached
        assertTrue(MoreReflection.accessField(FieldNameClass.class, "flag").isPresent());
    }

    @Test
    void shouldExtractTypeInformation() {
        assertEquals(String.class, MoreReflection.extractFirstGenericTypeArgument(StringTypedArrayList.class));
        assertThrows(IllegalArgumentException.class,
                () -> MoreReflection.extractFirstGenericTypeArgument(MoreReflectionTest.class));
        assertThrows(IllegalArgumentException.class, () -> MoreReflection.extractFirstGenericTypeArgument(List.class));

        assertFalse(MoreReflection.extractGenericTypeCovariantly(null).isPresent());
    }

    @Test
    void shouldExtractTypeInformationFromNestedGeneric() {
        assertEquals(List.class, MoreReflection.extractFirstGenericTypeArgument(NestedGenericSample.class));
    }

    @Test
    void shouldExtractTypeInformationFromNestedGenericBasedClass() {
        assertEquals(String.class, MoreReflection.extractFirstGenericTypeArgument(NestedGenericBaseClass.class));
    }

    @Test
    void shouldCreateProxy() {
        InvocationHandler handler = (proxy, method, args) -> null;
        assertNotNull(MoreReflection.newProxy(Collection.class, handler));
        assertThrows(IllegalArgumentException.class, () -> MoreReflection.newProxy(MoreReflection.class, handler));
    }

    @Test
    void shouldResolvePackageName() {
        assertEquals("de.cuioss.tools.reflect", MoreReflection.getPackageName(getClass()));
    }
}
