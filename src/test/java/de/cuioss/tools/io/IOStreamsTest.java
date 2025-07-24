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

import de.cuioss.tools.support.Generators;
import org.junit.jupiter.api.Test;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static de.cuioss.tools.io.IOStreams.contentEquals;
import static de.cuioss.tools.io.IOStreams.toInputStream;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/IOUtilsTestCase.java">...</a>
 *
 */
class IOStreamsTest {

    private static final int FILE_SIZE = 1024 * 4 + 1;

    private final byte[] inData = Generators.generateTestData(FILE_SIZE);

    @Test
    void contentEqualsInputStreamInputStream() throws Exception {
        var input1 = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
        assertTrue(contentEquals(input1, input1));
        input1 = new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8));
        assertTrue(contentEquals(input1, input1));
        assertTrue(contentEquals(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8))));
        assertTrue(contentEquals(new BufferedInputStream(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8))),
                new BufferedInputStream(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)))));
        assertTrue(contentEquals(new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8))));
        assertFalse(contentEquals(new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8))));
        assertFalse(contentEquals(new ByteArrayInputStream("ABC".getBytes(StandardCharsets.UTF_8)),
                new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void contentEqualsReaderReader() throws Exception {
        var input1 = new StringReader("");
        assertTrue(contentEquals(input1, input1));

        input1 = new StringReader("ABC");
        assertTrue(contentEquals(input1, input1));
        assertTrue(contentEquals(new StringReader(""), new StringReader("")));
        assertTrue(contentEquals(new BufferedReader(new StringReader("")), new BufferedReader(new StringReader(""))));
        assertTrue(contentEquals(new StringReader("ABC"), new StringReader("ABC")));
        assertFalse(contentEquals(new StringReader("ABCD"), new StringReader("ABC")));
        assertFalse(contentEquals(new StringReader("ABC"), new StringReader("ABCD")));
    }

    @Test
    void shouldProvideInputStream() throws IOException {
        assertTrue(contentEquals(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)), toInputStream(null)));
        assertFalse(
                contentEquals(new ByteArrayInputStream("ABCD".getBytes(StandardCharsets.UTF_8)), toInputStream("ABC")));
    }

    @Test
    void toByteArrayInputStream() throws Exception {
        try (InputStream fin = new ByteArrayInputStream(inData)) {
            final var out = IOStreams.toByteArray(fin);
            assertNotNull(out);
            assertEquals(0, fin.available(), "Not all bytes were read");
            assertArrayEquals(inData, out);
        }
    }

    @Test
    void toStringInputStream() throws Exception {
        try (InputStream fin = new ByteArrayInputStream(inData)) {
            var out = IOStreams.toString(fin, StandardCharsets.UTF_8);
            assertNotNull(out);
            assertEquals(0, fin.available(), "Not all bytes were read");
            assertArrayEquals(inData, out.getBytes());
        }
    }

}
