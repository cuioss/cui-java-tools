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
package de.cuioss.http.security.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL parameters containing null byte injection attacks.
 * Provides parameter strings with various null byte patterns.
 */
public class NullByteInjectionParameterGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> nullByteParameters = Generators.fixedValues(
            "param=value\0admin",
            "data=%00admin",
            "file=config\0",
            "user=test%00",
            "name=normal%00malicious",
            "path=safe.txt\0../../etc/passwd",
            "document=report.pdf%00.php",
            "upload=image.jpg\0shell.php",
            "config=settings.xml%00backup.sql",
            "log=access.log\0../../../sensitive.data",
            "backup=data.zip%00.exe",
            "script=normal.js\0malicious.php",
            "template=page.html%00admin.jsp",
            "resource=public.css\0private.cfg"
    );

    @Override
    public String next() {
        return nullByteParameters.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}