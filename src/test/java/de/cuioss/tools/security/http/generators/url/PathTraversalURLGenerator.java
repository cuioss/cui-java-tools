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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL paths containing path traversal attacks.
 * 
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
 * 
 * Provides various encoded path traversal patterns in URL context.
 */
public class PathTraversalURLGenerator implements TypedGenerator<String> {

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> encodingTypeGen = Generators.integers(1, 6);
    private final TypedGenerator<Integer> depthGen = Generators.integers(1, 4);
    private final TypedGenerator<String> apiPathGen = Generators.fixedValues("api", "files", "admin", "users", "docs", "backup", "upload", "download", "data", "content");
    private final TypedGenerator<String> targetGen = Generators.fixedValues("admin", "etc/passwd", "config", "windows", "etc/shadow", "etc/hosts", "var/log", "system32", "root", "root/.ssh");
    private final TypedGenerator<Boolean> mixedEncodingGen = Generators.booleans();

    @Override
    public String next() {
        return switch (encodingTypeGen.next()) {
            case 1 -> generateBasicEncodedTraversal();
            case 2 -> generateWindowsStyleTraversal();
            case 3 -> generateDoubleEncodedTraversal();
            case 4 -> generateMixedEncodingTraversal();
            case 5 -> generateLowercaseEncodedTraversal();
            case 6 -> generateMultipleDepthTraversal();
            default -> generateBasicEncodedTraversal();
        };
    }

    private String generateBasicEncodedTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2E%2E/");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateWindowsStyleTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2E%2E%5C");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateDoubleEncodedTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%252e%252e%252f");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateMixedEncodingTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");

        // Mix encoded and unencoded traversal
        for (int i = 0; i < depth; i++) {
            if (mixedEncodingGen.next()) {
                pattern.append("%2E%2E/");
            } else {
                pattern.append("../");
            }
        }

        // Sometimes add encoded target path
        if (mixedEncodingGen.next()) {
            pattern.append(target.replace("/", "%2f"));
        } else {
            pattern.append(target);
        }

        return pattern.toString();
    }

    private String generateLowercaseEncodedTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();
        int depth = depthGen.next();

        StringBuilder pattern = new StringBuilder("/" + apiPath + "/");
        for (int i = 0; i < depth; i++) {
            pattern.append("%2e%2e/");
        }
        pattern.append(target);

        return pattern.toString();
    }

    private String generateMultipleDepthTraversal() {
        String apiPath = apiPathGen.next();
        String target = targetGen.next();

        // Generate deep traversal pattern
        StringBuilder pattern = new StringBuilder("/" + apiPath + "/users/");

        // Add 3+ levels of traversal
        int deepDepth = Generators.integers(3, 6).next();
        for (int i = 0; i < deepDepth; i++) {
            pattern.append("%2E%2E%2F");
        }
        pattern.append(target);

        return pattern.toString();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}