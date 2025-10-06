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
package de.cuioss.tools.support;

import de.cuioss.test.generator.TypedGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Generator for test data byte arrays with a specific pattern.
 */
public class TestDataGenerator implements TypedGenerator<byte[]> {

    private final long size;

    /**
     * Creates a generator for byte arrays of specified size.
     *
     * @param size the size of the byte array to generate
     */
    public TestDataGenerator(long size) {
        this.size = size;
    }

    @Override
    public byte[] next() {
        try {
            final var baout = new ByteArrayOutputStream();
            generateTestData(baout, size);
            return baout.toByteArray();
        } catch (final IOException ioe) {
            throw new IllegalStateException("This should never happen: " + ioe.getMessage());
        }
    }

    @Override
    public Class<byte[]> getType() {
        return byte[].class;
    }

    private static void generateTestData(final OutputStream out, final long size) throws IOException {
        for (var i = 0; i < size; i++) {
            // nice varied byte pattern compatible with Readers and Writers
            out.write((byte) (i % 127 + 1));
        }
    }

    /**
     * Convenience factory method to create test data of specified size.
     *
     * @param size the size of the byte array
     * @return a byte array with test data
     */
    public static byte[] generateTestData(long size) {
        return new TestDataGenerator(size).next();
    }
}