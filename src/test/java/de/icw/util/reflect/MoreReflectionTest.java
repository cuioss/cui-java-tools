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
import de.icw.util.reflect.support.FileldNameClass;
import de.icw.util.reflect.support.MethodNameClass;
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
        assertEquals(2, MoreReflection.retrieveAccessMethods(MethodNameClass.class, Collections.emptyList()).size());
        assertEquals(1, MoreReflection.retrieveAccessMethods(MethodNameClass.class, Lists.newArrayList("name")).size());
    }

    @Test
    void shouldAccessModifierMethods() {
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "name", String.class).isPresent());
        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "flag", boolean.class).isPresent());

        assertTrue(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "builderWriteMethod", String.class)
                .isPresent());

        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "name", boolean.class).isPresent());
        assertFalse(MoreReflection.retrieveWriteMethod(MethodNameClass.class, "wrongParameterCount", String.class)
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

    @Test
    void shouldAccessField() {
        assertTrue(MoreReflection.accessField(FileldNameClass.class, "myField").isPresent());
        assertFalse(MoreReflection.accessField(FileldNameClass.class, "notThere").isPresent());
        // read from parent
        assertTrue(MoreReflection.accessField(FileldNameClass.class, "flag").isPresent());
    }
}
