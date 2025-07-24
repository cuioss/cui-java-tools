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
package de.cuioss.tools.io;

import org.junit.jupiter.api.Test;

import static de.cuioss.tools.io.FileTypePrefix.CLASSPATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileTypePrefixTest {

    @Test
    void removesCorrectPrefix() {
        assertEquals("foo", CLASSPATH.removePrefix("classpath:foo"));

        final var wrongValue = "klasspath:foo";
        assertEquals(wrongValue, CLASSPATH.removePrefix(wrongValue));
    }

    @Test
    void hasCorrectIdentity() {
        assertTrue(CLASSPATH.is("classpath:"));
        assertFalse(CLASSPATH.is(null));
    }

    @Test
    void toStringEqualsPrefix() {
        assertEquals(CLASSPATH.getPrefix(), CLASSPATH.toString());
    }
}
