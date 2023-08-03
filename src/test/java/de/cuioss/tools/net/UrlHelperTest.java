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
import static de.cuioss.tools.net.UrlHelper.addPrecedingSlashToPath;
import static de.cuioss.tools.net.UrlHelper.addTrailingSlashToUrl;
import static de.cuioss.tools.net.UrlHelper.removePrecedingSlashFromPath;
import static de.cuioss.tools.net.UrlHelper.removeTrailingSlashesFromUrl;
import static de.cuioss.tools.net.UrlHelper.splitPath;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class UrlHelperTest {

    private static final String DOUBLE_SLASHED = "a/b/c//";
    private static final String SLASHED = "a/b/c/";
    private static final String NOT_SLASHED = "a/b/c";
    private static final String PRECEDING_SLASHED = "/a/b/c";
    private static final String DOUBLE_PRECEDING_SLASHED = "//a/b/c";
    private static final String VALID_URI = "https://foo.bar";
    private static final String INVALID_URI = "~~b:0:0:m~~";

    @Test
    void shouldSuffixSlashToUrls() {
        assertEquals("", addTrailingSlashToUrl(""));
        assertEquals(SLASHED, addTrailingSlashToUrl(SLASHED));
        assertEquals(SLASHED, addTrailingSlashToUrl(NOT_SLASHED));
    }

    @Test
    void shouldRemoveTrailingSlashFromUrls() {
        assertEquals("", removeTrailingSlashesFromUrl(""));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(NOT_SLASHED));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(SLASHED));
        assertEquals(NOT_SLASHED, removeTrailingSlashesFromUrl(DOUBLE_SLASHED));
    }

    @Test
    void shouldRemovePrecedingSlash() {
        assertEquals("", removePrecedingSlashFromPath(""));
        assertEquals(NOT_SLASHED, removePrecedingSlashFromPath(PRECEDING_SLASHED));
        assertEquals(NOT_SLASHED, removePrecedingSlashFromPath(NOT_SLASHED));
        assertEquals(NOT_SLASHED, removePrecedingSlashFromPath(DOUBLE_PRECEDING_SLASHED));
    }

    @Test
    void shouldAddPrecedingSlash() {
        assertEquals("/", addPrecedingSlashToPath(""));
        assertEquals(PRECEDING_SLASHED, addPrecedingSlashToPath(PRECEDING_SLASHED));
        assertEquals(PRECEDING_SLASHED, addPrecedingSlashToPath(NOT_SLASHED));
    }

    @Test
    void shouldSplitIntoSegments() {
        assertTrue(splitPath("").isEmpty());
        assertTrue(splitPath("/").isEmpty());
        assertFalse(splitPath(SLASHED).isEmpty());
        List<String> result = immutableList("a", "b", "c");
        assertEquals(result, splitPath(DOUBLE_SLASHED));
        assertEquals(result, splitPath(SLASHED));
        assertEquals(result, splitPath(NOT_SLASHED));
        assertEquals(result, splitPath("a/b /c"));
        assertEquals(result, splitPath("a/b//c"));
    }

    @Test
    void parsesValidUri() {
        Optional<URI> result = assertDoesNotThrow(() -> UrlHelper.tryParseUri(VALID_URI));
        assertTrue(result.isPresent());
        assertEquals(VALID_URI, result.get().toString());
    }

    @Test
    void parsesInvalidUri() {
        Optional<URI> result = assertDoesNotThrow(() -> UrlHelper.tryParseUri(INVALID_URI));
        assertTrue(result.isEmpty());
    }

    @Test
    void checksValidUri() {
        assertTrue(assertDoesNotThrow(() -> UrlHelper.isValidUri(VALID_URI)));
    }

    @Test
    void checksInvalidUri() {
        assertFalse(assertDoesNotThrow(() -> UrlHelper.isValidUri(INVALID_URI)));
    }
}
