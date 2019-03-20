package de.icw.util.reflect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import javax.annotation.Resource;

import org.junit.jupiter.api.Test;

import com.google.common.collect.Lists;

import de.icw.util.reflect.support.ChildAnnotatedClass;
import de.icw.util.reflect.support.MethodNameTests;
import de.icw.util.reflect.support.NotAnnotatedClass;

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
        assertTrue(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "name").isPresent());
        assertTrue(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "flag").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "protected").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "private").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "module").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "static").isPresent());
        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "wrongName").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "class").isPresent());

        assertFalse(MoreReflection.retrieveAccessMethod(MethodNameTests.class, "wrongParameter").isPresent());
    }

    @Test
    void shouldFilterAccessGetterMethods() {
        assertEquals(2, MoreReflection.retrieveAccessMethods(MethodNameTests.class, Collections.emptyList()).size());
        assertEquals(1, MoreReflection.retrieveAccessMethods(MethodNameTests.class, Lists.newArrayList("name")).size());
    }

    @Test
    void shouldAccessModifierMethods() {
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameTests.class, "name", String.class).isPresent());
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameTests.class, "flag", boolean.class).isPresent());

        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameTests.class, "builderWriteMethod", String.class)
                .isPresent());

        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameTests.class, "name", boolean.class).isPresent());
        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameTests.class, "wrongParameterCount", String.class)
                .isPresent());
    }

    @Test
    void shouldExtractAllAnnotations() {
        assertTrue(MoreReflection.extractAllAnnotations(null, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(NotAnnotatedClass.class, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(Object.class, Resource.class).isEmpty());
        assertTrue(MoreReflection.extractAllAnnotations(List.class, Resource.class).isEmpty());

        assertEquals(1,
                MoreReflection.extractAllAnnotations(ChildAnnotatedClass.class, Deprecated.class).size());
        assertEquals(2,
                MoreReflection.extractAllAnnotations(ChildAnnotatedClass.class, Resource.class)
                        .size());

    }

    @Test
    void shouldExtractSingleAnnotations() {
        assertFalse(MoreReflection.extractAnnotation(null, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(NotAnnotatedClass.class, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(Object.class, Resource.class).isPresent());
        assertFalse(MoreReflection.extractAnnotation(List.class, Resource.class).isPresent());

        assertTrue(
                MoreReflection.extractAnnotation(ChildAnnotatedClass.class, Deprecated.class).isPresent());
        assertTrue(
                MoreReflection.extractAnnotation(ChildAnnotatedClass.class, Resource.class)
                        .isPresent());

    }

}
