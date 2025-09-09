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
 * Generates legitimate URLs that should pass validation.
 * Implements: Task G5 from HTTP verification specification
 */
public class ValidURLGenerator implements TypedGenerator<String> {

    private static final TypedGenerator<String> VALID_PATHS = Generators.fixedValues(
            "/api/v1/users",
            "/static/css/style.css",
            "/index.html",
            "/docs/guide.pdf",
            "/search?q=test&limit=10",
            "/products/123/reviews",
            "/admin/dashboard"
    );

    private static final TypedGenerator<String> SORT_OPTIONS = Generators.fixedValues("asc", "desc");

    // TODO: Replace with UrlSecurityConfig.DEFAULT_MAX_PATH_LENGTH once available (Phase 3)
    private static final int DEFAULT_MAX_PATH_LENGTH = 2048;

    private final TypedGenerator<Boolean> paramGen = Generators.booleans();
    private final TypedGenerator<Integer> pageGen = Generators.integers(1, 100);

    @Override
    public String next() {
        String path = VALID_PATHS.next();

        if (paramGen.next()) {
            // Add valid parameters (check if path already has parameters)
            if (path.contains("?")) {
                // Path already has parameters, add with &
                path += "&page=" + pageGen.next();
                path += "&sort=" + SORT_OPTIONS.next();
            } else {
                // Path doesn't have parameters, add with ?
                path += "?page=" + pageGen.next();
                path += "&sort=" + SORT_OPTIONS.next();
            }
        }

        // Ensure within DEFAULT_MAX_PATH_LENGTH (2048)
        if (path.length() > DEFAULT_MAX_PATH_LENGTH) {
            path = path.substring(0, DEFAULT_MAX_PATH_LENGTH);
        }

        return path;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}