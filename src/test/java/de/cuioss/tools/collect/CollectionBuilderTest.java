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
package de.cuioss.tools.collect;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static de.cuioss.tools.collect.CollectionLiterals.*;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CollectionBuilder should")
class CollectionBuilderTest {

    @Nested
    @DisplayName("handle add operations")
    class AddOperations {

        @Test
        @DisplayName("handle various add methods")
        void shouldHandleAddMethods() {
            final var builder = new CollectionBuilder<String>();
            builder.add("1");
            assertEquals(1, builder.size());
            builder.add("2", "3");
            assertEquals(3, builder.size());
            builder.add(Arrays.asList("4", "5"));
            assertEquals(5, builder.size());
            builder.add(Stream.of("6", "7"));
            assertEquals(7, builder.size());
            builder.add((Iterable<String>) Arrays.asList("8", "9"));
            assertEquals(9, builder.size());
            builder.add(Optional.of("10"));
            assertEquals(10, builder.size());
            builder.add(Optional.empty());
            assertEquals(10, builder.size());
            builder.add((String[]) null);
            assertEquals(10, builder.size());
        }

        @Test
        @DisplayName("handle add with null values when enabled")
        void shouldHandleAddIfPresentMethods() {
            final var builder = new CollectionBuilder<String>().addNullValues(true);
            builder.add("1");
            assertEquals(1, builder.size());
            builder.add(new String[]{null});
            assertEquals(2, builder.size());
            builder.add("2", "3");
            assertEquals(4, builder.size());
            builder.add(Arrays.asList("4", "5", null));
            assertEquals(7, builder.size());
            builder.add(Stream.of("6", "7", null));
            assertEquals(10, builder.size());
            builder.add((Iterable<String>) Arrays.asList("8", "9", null));
            assertEquals(13, builder.size());
        }

        @Test
        @DisplayName("handle additional collection operations")
        void shouldHandleAdditionalMethods() {
            final var builder = new CollectionBuilder<String>();
            builder.add("1");
            assertEquals(1, builder.size());
            assertTrue(builder.contains("1"));
            assertEquals("1", builder.iterator().next());
            builder.clear();
            assertEquals(0, builder.size());
            assertTrue(builder.isEmpty());
        }
    }

    @Nested
    @DisplayName("handle object operations")
    class ObjectOperations {

        @Test
        @DisplayName("properly implement Object methods")
        void shouldHandleObjectMethods() {
            final var builder = new CollectionBuilder<String>();
            builder.add("1");
            assertNotNull(builder.toString());
            assertDoesNotThrow(builder::hashCode);
            assertNotEquals(0, builder.hashCode());
            assertEquals(builder, builder);
        }
    }

    @Nested
    @DisplayName("handle collection variants")
    class CollectionVariants {

        @Test
        @DisplayName("build different collection types")
        void shouldBuildCollectionVariants() {
            final var builder = new CollectionBuilder<>(mutableList("1", "2", "3", "4", "4"));

            assertMutable(builder.toMutableList());
            assertEquals(5, builder.toMutableList().size());

            assertImmutable(builder.toImmutableList());
            assertEquals(5, builder.toImmutableList().size());

            assertMutable(builder.toMutableSet());
            assertEquals(4, builder.toMutableSet().size());

            assertImmutable(builder.toImmutableSet());
            assertEquals(4, builder.toImmutableSet().size());

            assertMutable(builder.toMutableNavigableSet());
            assertEquals(4, builder.toMutableNavigableSet().size());

            assertImmutable(builder.toImmutableNavigableSet());
            assertEquals(4, builder.toImmutableNavigableSet().size());

            assertMutable(builder.toConcurrentList());
            assertEquals(5, builder.toConcurrentList().size());

            assertMutable(builder.toConcurrentSet());
            assertEquals(4, builder.toConcurrentSet().size());

            assertMutable(builder.toConcurrentNavigableSet());
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("convert to array")
        void shouldReturnArray() {
            final var builder = new CollectionBuilder<String>();
            assertNotNull(builder.toArray(String.class));
            assertEquals(0, builder.toArray(String.class).length);

            builder.add(mutableList("1", "2", "3", "4", "4"));
            assertNotNull(builder.toArray(String.class));
            assertEquals(5, builder.toArray(String.class).length);
        }
    }

    @Nested
    @DisplayName("handle copy operations")
    class CopyOperations {

        @Test
        @DisplayName("copy from list")
        void shouldCreateCopyFromList() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3"));
            builder.add("4");
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("copy from iterator")
        void shouldCreateCopyFromIterator() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").iterator());
            builder.add("4");
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("copy from iterable")
        void shouldCreateCopyFromIterable() {
            final CollectionBuilder<String> builder = CollectionBuilder
                    .copyFrom((Iterable<String>) immutableList("1", "2", "3"));
            builder.add("4");
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("copy from stream")
        void shouldCreateCopyFromStream() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("1", "2", "3").stream());
            builder.add("4");
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("copy from varargs")
        void shouldCreateCopyFromVarargs() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1", "2", "3");
            builder.add("4");
            assertEquals(4, builder.toConcurrentNavigableSet().size());
        }

        @Test
        @DisplayName("copy from single parameter")
        void shouldCreateCopyFromSingleParam() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom("1");
            builder.add("4");
            assertEquals(2, builder.toConcurrentNavigableSet().size());
        }
    }

    @Nested
    @DisplayName("handle sorting and filtering")
    class SortingAndFiltering {

        @Test
        @DisplayName("sort list elements")
        void shouldSort() {
            final CollectionBuilder<String> builder = CollectionBuilder.copyFrom(immutableList("3", "2", "1"));
            assertEquals(Arrays.asList("3", "2", "1"), builder.toMutableList());
            builder.sort(Comparator.naturalOrder());
            assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
        }

        @Test
        @DisplayName("sort non-list collections")
        void shouldSortNonLists() {
            final var builder = new CollectionBuilder<>(mutableSortedSet("3", "2", "1"));
            builder.sort(Comparator.naturalOrder());
            assertEquals(Arrays.asList("1", "2", "3"), builder.toMutableList());
        }

        @Test
        @DisplayName("filter null values by default")
        void shouldFilterNullsByDefault() {
            final List<String> testArray = new ArrayList<>(0);
            testArray.add("first");
            testArray.add(null);
            testArray.add("second");

            final var result = new CollectionBuilder<String>().add(testArray).toImmutableList();

            assertEquals(2, result.size(), "Only two entries expected");
            assertNotEquals(testArray, result);
        }
    }

    static void assertMutable(final Collection<String> collection) {
        assertNotNull(collection);
        collection.add("I am mutable");
    }

    static void assertImmutable(final Collection<String> collection) {
        assertNotNull(collection);
        assertThrows(UnsupportedOperationException.class, () ->
                collection.add("i am not mutable"));
    }
}
