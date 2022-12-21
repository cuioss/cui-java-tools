package io.cui.tools.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

@SuppressWarnings("javadoc")
public class TestLogHandler extends Handler {

    List<LogRecord> records = new ArrayList<>();

    Level lastLevel = Level.FINEST;

    @Override
    public void publish(LogRecord record) {
        records.add(record);
    }

    @Override
    public void close() {
    }

    @Override
    public void flush() {
    }

    void assertMessagePresent(String message, Level level) {
        assertFalse(records.isEmpty());
        assertEquals(1, records.stream().filter(r -> level.equals(r.getLevel()))
                .filter(r -> message.equals(r.getMessage())).count());
    }

    void assertMessagePresent(String message, Level level, Throwable throwable) {
        assertFalse(records.isEmpty());
        assertEquals(1, records.stream().filter(r -> level.equals(r.getLevel()))
                .filter(r -> message.equals(r.getMessage())).filter(r -> throwable.equals(r.getThrown())).count());
    }

    void clearRecords() {
        records.clear();
    }
}
