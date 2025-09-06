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
package de.cuioss.tools.security.http.generators;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL paths containing null byte injection attacks.
 * Provides various null byte patterns in URL context.
 */
public class NullByteURLGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> nullByteURLs = Generators.fixedValues(
            "/api/users\0admin",
            "/api/users%00admin",
            "/api\0/users",
            "/api/users/123\0",
            "/api/files\0.php",
            "/api/download\0../../../etc/passwd",
            "/api/config%00.txt",
            "/api/upload/file.jpg\0.php",
            "/api/docs/readme\0.html",
            "/api/admin\0/secret",
            "/api/data%00/config",
            "/api/backup\0.tar.gz",
            "/api/logs/error.log\0",
            "/api/scripts%00.sh",
            "/api/images/photo.png\0.php"
    );

    @Override
    public String next() {
        return nullByteURLs.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}