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
package de.cuioss.tools.formatting.template.token;

import de.cuioss.tools.support.Generators;
import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

class ActionTokenTest {

    @Test
    void shouldImplementObjectContracts() {
        var token = Generators.randomString();
        var template = "prefix" + token + "suffix";
        ObjectMethodsAsserts.assertNiceObject(new ActionToken(template, token));
    }

}
