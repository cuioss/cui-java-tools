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
package de.cuioss.tools.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogRecordModelTest {

    private static final String PREFIX = "CUI-100";

    private final LogRecord model = LogRecordModel.builder().identifier(100).prefix("CUI").template("{}-%s").build();

    @Test
    void shouldHandlePrefix() {
        assertEquals(PREFIX, model.resolveIdentifierString());
        assertEquals(PREFIX + ": A-2", model.format("A", 2));
        // Should be reentrant
        assertEquals(PREFIX + ": A-2", model.format("A", 2));
    }

    @Test
    void shouldHandleSupplier() {
        var supplier = model.supplier("A", 2);
        assertEquals(PREFIX + ": A-2", supplier.get());
    }

}
