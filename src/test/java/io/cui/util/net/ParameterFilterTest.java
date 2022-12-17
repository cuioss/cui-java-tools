package io.cui.util.net;

import static io.cui.util.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.cui.util.support.ObjectMethodsAsserts;

class ParameterFilterTest {

    private static final String JAVAX_FACES = "javax.faces";

    private static final List<String> EXCLUDES = immutableList("a", "b", "c");
    private static final List<String> INCLUDES = immutableList("d", "e", "f", "af", "fa");

    private static final List<String> FACES_INCLUDES =
        immutableList("d" + JAVAX_FACES, "e" + JAVAX_FACES,
                "f" + JAVAX_FACES);

    private static final List<String> FACES_EXCLUDES =
        immutableList(JAVAX_FACES + "a", JAVAX_FACES + "." + "b",
                JAVAX_FACES + "-" + "c");

    @Test
    void testShouldExludeAndIncludeStrings() {
        final ParameterFilter filter = new ParameterFilter(EXCLUDES, false);
        for (final String exclude : EXCLUDES) {
            assertTrue(filter.isExcluded(exclude));
        }
        for (final String include : INCLUDES) {
            assertFalse(filter.isExcluded(include));
        }
    }

    @Test
    void testShouldExludeAndIncludeFacesStrings() {
        final ParameterFilter filter = new ParameterFilter(EXCLUDES, true);
        for (final String exclude : FACES_EXCLUDES) {
            assertTrue(filter.isExcluded(exclude));
        }
        for (final String include : FACES_INCLUDES) {
            assertFalse(filter.isExcluded(include));
        }
    }

    @Test
    void shouldBehaveWell() {
        ObjectMethodsAsserts.assertNiceObject(new ParameterFilter(EXCLUDES, true));
    }

}