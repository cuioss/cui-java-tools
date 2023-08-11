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
package de.cuioss.tools.support;

import static de.cuioss.tools.base.Preconditions.checkArgument;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Provides a number of simple generators for unit-tests
 *
 * @author Oliver Wolff
 *
 */
@SuppressWarnings("javadoc")
public class Generators {

    /**
     * @param count
     * @return a {@link List} containing a number random String derived by
     *         {@link UUID}
     */
    public static List<String> randomStrings(int count) {
        List<String> result = new ArrayList<>();
        for (var i = 0; i < count; i++) {
            result.add(randomString());
        }
        return result;
    }

    /**
     * @return a {@link List} containing a number random String derived by
     *         {@link UUID}
     */
    public static String randomString() {
        return UUID.randomUUID().toString();
    }

    /**
     * @param lowerBound
     * @param upperBound
     * @return a pseudo random number in between the given boundaries
     */
    public static int randomInt(int lowerBound, int upperBound) {
        checkArgument(upperBound > lowerBound, "UpperBound must be larger than lower bound");
        return ThreadLocalRandom.current().nextInt(lowerBound, upperBound + 1);
    }

    /**
     * @return a pseudo random boolean
     */
    public static boolean randomBoolean() {
        return ThreadLocalRandom.current().nextBoolean();
    }

    public static byte[] generateTestData(final long size) {
        try {
            final var baout = new ByteArrayOutputStream();
            generateTestData(baout, size);
            return baout.toByteArray();
        } catch (final IOException ioe) {
            throw new RuntimeException("This should never happen: " + ioe.getMessage());
        }
    }

    public static void generateTestData(final OutputStream out, final long size) throws IOException {
        for (var i = 0; i < size; i++) {
            // output.write((byte)'X');

            // nice varied byte pattern compatible with Readers and Writers
            out.write((byte) (i % 127 + 1));
        }
    }
}
