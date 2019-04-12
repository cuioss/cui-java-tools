package de.icw.util.runner.support;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Helper class that catches the last 1000-line of a given log output
 *
 * @author Oliver Wolff
 *
 */
public class ConsoleOutputBuffer extends LogOutputStream {

    private Queue<String> messages = new LinkedBlockingQueue<>(1000);

    @Override
    protected void processLine(String line) {
        messages.add(line);
    }

    /**
     * @return the oldest entry / line available
     */
    public Optional<String> getOldestEntry() {
        return Optional.ofNullable(messages.element());
    }

    /**
     * @return the oldest entry / line available
     */
    public Optional<String> getNewestEntry() {
        return Optional.ofNullable(messages.peek());
    }

    /**
     * @return a copy of the current entries in this buffer.
     */
    public List<String> getSnapshot() {
        return new ArrayList<>(messages);
    }

    /**
     * @return the size of the contained {@link Queue}
     */
    public int size() {
        return messages.size();
    }

}
