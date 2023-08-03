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

import java.util.logging.Level;

import org.junit.jupiter.api.Test;

class LogLevelTest {

    @Test
    void convertJuliLevelToCuiLevel() {
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.ALL));
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.FINEST));
        assertEquals(LogLevel.TRACE, LogLevel.from(Level.FINER));

        assertEquals(LogLevel.DEBUG, LogLevel.from(Level.FINE));
        assertEquals(LogLevel.DEBUG, LogLevel.from(Level.CONFIG));

        assertEquals(LogLevel.INFO, LogLevel.from(Level.INFO));

        assertEquals(LogLevel.WARN, LogLevel.from(Level.WARNING));

        assertEquals(LogLevel.ERROR, LogLevel.from(Level.SEVERE));

        assertEquals(LogLevel.OFF, LogLevel.from(Level.OFF));
    }
}
