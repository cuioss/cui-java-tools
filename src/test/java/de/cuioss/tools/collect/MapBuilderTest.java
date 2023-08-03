package de.cuioss.tools.collect;

import static de.cuioss.tools.collect.CollectionLiterals.immutableMap;
import static de.cuioss.tools.collect.CollectionLiteralsTest.assertImmutable;
import static de.cuioss.tools.collect.CollectionLiteralsTest.assertMutable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MapBuilderTest {

    private static final String KEY_1 = "key1";
    private static final String KEY_2 = "key2";
    private static final String KEY_3 = "key3";

    private static final String VALUE_1 = "value1";
    private static final String VALUE_2 = "value2";

    @Test
    void shouldHandleEmptyMap() {
        var builder = new MapBuilder<String, String>();
        assertMutable(builder.toMutableMap());
        assertImmutable(builder.toImmutableMap());
    }

    @Test
    void shouldHandleHappyCase() {
        var builder = new MapBuilder<String, String>();
        builder.put(KEY_1, VALUE_1).put(KEY_2, VALUE_2);
        assertEquals(2, builder.size());
        assertMutable(builder.toMutableMap());
        assertImmutable(builder.toImmutableMap());
    }

    @Test
    void shouldHandleRemove() {
        var builder = new MapBuilder<String, String>();
        builder.put(KEY_1, VALUE_1).remove(KEY_1);
        assertTrue(builder.isEmpty());
        assertEquals(0, builder.size());
        assertMutable(builder.toMutableMap());
        assertImmutable(builder.toImmutableMap());
    }

    @Test
    void shouldHandleClear() {
        var builder = new MapBuilder<String, String>();
        assertTrue(builder.isEmpty());
        assertTrue(builder.clear().isEmpty());
        builder.put(KEY_1, VALUE_1);
        assertFalse(builder.isEmpty());
        assertTrue(builder.clear().isEmpty());
    }

    @Test
    void shouldHandlePutAll() {
        var builder = new MapBuilder<String, String>();
        builder.putAll(new MapBuilder<String, String>().put(KEY_1, VALUE_1).toImmutableMap());
        assertFalse(builder.isEmpty());
    }

    @Test
    void shouldHandlePutEntry() {
        var builder = new MapBuilder<String, String>();
        builder.put(new MapBuilder<String, String>().put(KEY_1, VALUE_1).toImmutableMap().entrySet().iterator().next());
        assertFalse(builder.isEmpty());
    }

    @Test
    void shouldHandleContainsKeyValue() {
        var builder = new MapBuilder<String, String>();
        assertFalse(builder.containsKey(KEY_1));
        assertFalse(builder.containsValue(VALUE_1));
        builder.put(KEY_1, VALUE_1);
        assertTrue(builder.containsKey(KEY_1));
        assertTrue(builder.containsValue(VALUE_1));
    }

    @Test
    void shouldHandleCopyFromMap() {
        MapBuilder<String, String> builder = MapBuilder.copyFrom(immutableMap(KEY_2, VALUE_2));
        builder.put(KEY_1, VALUE_1);
        assertFalse(builder.isEmpty());
        assertEquals(2, builder.size());
    }

    @Test
    void shouldHandleLiteralCopy() {
        assertEquals(1, MapBuilder.from(KEY_1, 1).size());
        assertEquals(2, MapBuilder.from(KEY_1, 1, KEY_2, 2).size());
        assertEquals(3, MapBuilder.from(KEY_1, 1, KEY_2, 2, KEY_3, 3).size());
        assertEquals(4, MapBuilder.from(KEY_1, 1, KEY_2, 2, KEY_3, 3, "key4", 4).size());
    }

    @Test
    void shouldOnlyAddIfNotNull() {
        final var map = new MapBuilder<String, String>().put(KEY_1, null).putIfNotNull(KEY_2, null)
                .putIfNotNull(KEY_3, "").toImmutableMap();
        assertTrue(map.containsKey(KEY_1));
        assertFalse(map.containsKey(KEY_2));
        assertTrue(map.containsKey(KEY_3));
    }
}
