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
package de.cuioss.tools.string;

import static de.cuioss.tools.collect.CollectionLiterals.mutableList;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Initially taken from
 * https://github.com/google/guava/blob/master/guava-tests/test/com/google/common/base/JoinerTest.java
 */
class JoinerTest {

    private static final Joiner J = Joiner.on("-");

    // <Integer> needed to prevent warning :(
    private static final Iterable<Integer> ITERABLE_EMPTY = List.of();
    private static final Iterable<Integer> ITERABLE_1 = List.of(1);
    private static final Iterable<Integer> ITERABLE_12 = Arrays.asList(1, 2);
    private static final Iterable<Integer> ITERABLE_123 = Arrays.asList(1, 2, 3);
    private static final Iterable<Integer> ITERABLE_NULL = Collections.singletonList((Integer) null);
    private static final Iterable<Integer> ITERABLE_NULL_NULL = Arrays.asList(null, null);
    private static final Iterable<Integer> ITERABLE_NULL_1 = Arrays.asList(null, 1);
    private static final Iterable<Integer> ITERABLE_1_NULL = Arrays.asList(1, null);
    private static final Iterable<Integer> ITERABLE_1_NULL_2 = Arrays.asList(1, null, 2);
    private static final Iterable<Integer> ITERABLE_FOUR_NULLS = Arrays.asList(null, null, null, null);

    @Test
    void testOnCharOverride() {
        final var onChar = Joiner.on('-');
        assertNoOutput(onChar, ITERABLE_EMPTY);
        assertResult(onChar, ITERABLE_1, "1");
        assertResult(onChar, ITERABLE_12, "1-2");
        assertResult(onChar, ITERABLE_123, "1-2-3");
    }

    @Test
    void testSkipNulls() {
        final var skipNulls = J.skipNulls();
        assertNoOutput(skipNulls, ITERABLE_EMPTY);
        assertNoOutput(skipNulls, ITERABLE_NULL);
        assertNoOutput(skipNulls, ITERABLE_NULL_NULL);
        assertNoOutput(skipNulls, ITERABLE_FOUR_NULLS);
        assertResult(skipNulls, ITERABLE_1, "1");
        assertResult(skipNulls, ITERABLE_12, "1-2");
        assertResult(skipNulls, ITERABLE_123, "1-2-3");
        assertResult(skipNulls, ITERABLE_NULL_1, "1");
        assertResult(skipNulls, ITERABLE_1_NULL, "1");
        assertResult(skipNulls, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testSkipEmptyStrings() {
        final var skipEmptyStrings = J.skipEmptyStrings().skipNulls();
        assertNoOutput(skipEmptyStrings, ITERABLE_EMPTY);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_FOUR_NULLS);
        assertResult(skipEmptyStrings, mutableList("1"), "1");
        assertResult(skipEmptyStrings, mutableList("1", ""), "1");
        assertResult(skipEmptyStrings, mutableList("1", "2"), "1-2");
        assertResult(skipEmptyStrings, mutableList("1", "2", ""), "1-2");
        assertResult(skipEmptyStrings, mutableList("", "1", "2", ""), "1-2");
        assertResult(skipEmptyStrings, ITERABLE_123, "1-2-3");
        assertResult(skipEmptyStrings, ITERABLE_NULL_1, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testSkipBlankStrings() {
        final var skipEmptyStrings = J.skipBlankStrings().skipNulls();
        assertNoOutput(skipEmptyStrings, ITERABLE_EMPTY);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_NULL_NULL);
        assertNoOutput(skipEmptyStrings, ITERABLE_FOUR_NULLS);
        assertResult(skipEmptyStrings, mutableList("1"), "1");
        assertResult(skipEmptyStrings, mutableList("1", "  "), "1");
        assertResult(skipEmptyStrings, mutableList("1", "2"), "1-2");
        assertResult(skipEmptyStrings, mutableList("1", "2", "  "), "1-2");
        assertResult(skipEmptyStrings, mutableList("", "1", "2", "   "), "1-2");
        assertResult(skipEmptyStrings, ITERABLE_123, "1-2-3");
        assertResult(skipEmptyStrings, ITERABLE_NULL_1, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL, "1");
        assertResult(skipEmptyStrings, ITERABLE_1_NULL_2, "1-2");
    }

    @Test
    void testUseForNull() {
        final var zeroForNull = J.useForNull("0");
        assertNoOutput(zeroForNull, ITERABLE_EMPTY);
        assertResult(zeroForNull, ITERABLE_1, "1");
        assertResult(zeroForNull, ITERABLE_12, "1-2");
        assertResult(zeroForNull, ITERABLE_123, "1-2-3");
        assertResult(zeroForNull, ITERABLE_NULL, "0");
        assertResult(zeroForNull, ITERABLE_NULL_NULL, "0-0");
        assertResult(zeroForNull, ITERABLE_NULL_1, "0-1");
        assertResult(zeroForNull, ITERABLE_1_NULL, "1-0");
        assertResult(zeroForNull, ITERABLE_1_NULL_2, "1-0-2");
        assertResult(zeroForNull, ITERABLE_FOUR_NULLS, "0-0-0-0");
    }

    private static void assertNoOutput(final Joiner joiner, final Iterable<?> set) {
        assertEquals("", joiner.join(set));
    }

    private static void assertResult(final Joiner joiner, final Iterable<?> parts, final String expected) {
        assertEquals(expected, joiner.join(parts));
        assertEquals(expected, joiner.join(parts.iterator()));
    }

}
