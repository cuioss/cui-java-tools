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
package de.cuioss.tools.net;

import static de.cuioss.tools.collect.CollectionLiterals.immutableList;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

import java.util.List;

class ParameterFilterTest {

    private static final String JAVAX_FACES = "javax.faces";

    private static final List<String> EXCLUDES = immutableList("a", "b", "c");
    private static final List<String> INCLUDES = immutableList("d", "e", "f", "af", "fa");

    private static final List<String> FACES_INCLUDES = immutableList("d" + JAVAX_FACES, "e" + JAVAX_FACES,
            "f" + JAVAX_FACES);

    private static final List<String> FACES_EXCLUDES = immutableList(JAVAX_FACES + "a", JAVAX_FACES + "." + "b",
            JAVAX_FACES + "-" + "c");

    @Test
    void testShouldExludeAndIncludeStrings() {
        final var filter = new ParameterFilter(EXCLUDES, false);
        for (final String exclude : EXCLUDES) {
            assertTrue(filter.isExcluded(exclude));
        }
        for (final String include : INCLUDES) {
            assertFalse(filter.isExcluded(include));
        }
    }

    @Test
    void testShouldExludeAndIncludeFacesStrings() {
        final var filter = new ParameterFilter(EXCLUDES, true);
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
