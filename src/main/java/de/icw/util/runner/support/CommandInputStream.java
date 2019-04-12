package de.icw.util.runner.support;

import static com.google.common.base.Strings.emptyToNull;
import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * While {@link ConsoleOutputBuffer} fetches the output of a process this class can provide inputs
 * for sending commands to the wrapped process
 *
 * @author Oliver Wolff
 *
 */
public class CommandInputStream extends InputStream {

    private final LinkedBlockingDeque<Integer> commandElements = new LinkedBlockingDeque<>();

    @Override
    public int read() throws IOException {
        try {
            return commandElements.takeLast();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    /**
     * @param command to be sent must not be null nor empty
     */
    public void sendCommand(String command) {
        requireNonNull(emptyToNull(command));
        synchronized (commandElements) {
            for (byte element : command.getBytes()) {
                commandElements.add((int) element);
            }
        }
    }
}
