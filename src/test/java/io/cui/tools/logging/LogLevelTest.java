package io.cui.tools.logging;

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
