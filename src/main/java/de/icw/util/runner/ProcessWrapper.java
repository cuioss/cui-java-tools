package de.icw.util.runner;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import de.icw.util.logging.Logger;
import de.icw.util.runner.support.CommandInputStream;
import de.icw.util.runner.support.ConsoleOutputBuffer;
import de.icw.util.runner.support.PumpStreamHandler;
import de.icw.util.runner.support.TimeoutProcessCloser;
import lombok.Getter;
import lombok.Setter;

/**
 * Wraps a process, provides convenient methods to the output / input streams.
 *
 * @author Oliver Wolff
 *
 */
public class ProcessWrapper {

    private static final Logger log = new Logger(ProcessWrapper.class);

    @Getter
    private final Process wrapped;

    @Getter
    private final PumpStreamHandler streams;

    private final ConsoleOutputBuffer outputBuffer;

    private final CommandInputStream commandInput;

    /**
     * Defines the number of seconds to wait as upper bound in order to close the streams. Default
     * to 10 s.
     */
    @Setter
    private int streamCloseTimeout = 10;

    private boolean streamClosed = false;

    /**
     * @param process to be wrapped, must not be null
     */
    public ProcessWrapper(Process process) {
        wrapped = requireNonNull(process);
        outputBuffer = new ConsoleOutputBuffer();
        commandInput = new CommandInputStream();
        streams = new PumpStreamHandler(outputBuffer, outputBuffer, commandInput);

        streams.setProcessInputStream(process.getOutputStream());
        streams.setProcessOutputStream(process.getInputStream());
        streams.start();
    }

    /**
     * @return the oldest entry / line available
     */
    public Optional<String> getOldestEntry() {
        return outputBuffer.getOldestEntry();
    }

    /**
     * @return the oldest entry / line available
     */
    public Optional<String> getNewestEntry() {
        return outputBuffer.getNewestEntry();
    }

    /**
     * @return a copy of the current entries in this buffer.
     */
    public List<String> getConsoleContent() {
        return outputBuffer.getSnapshot();
    }

    /**
     * @param command to be sent must not be null nor empty
     */
    public void sendCommand(String command) {
        commandInput.sendCommand(command);
    }

    /**
     * @return see {@link Process#isAlive()}
     */
    public boolean isAlive() {
        return wrapped.isAlive();
    }

    /**
     * @param timeout
     * @param unit
     * @return {@link Process#waitFor(long, TimeUnit)}
     * @throws InterruptedException
     */
    public boolean waitFor(long timeout, TimeUnit unit)
        throws InterruptedException {
        return wrapped.waitFor(timeout, unit);
    }

    /**
     * Kills the subprocess. Whether the subprocess represented by this
     * {@code Process} object is forcibly terminated or not is
     * implementation dependent.
     */
    public void destroy() {
        wrapped.destroy();
    }

    /**
     * see {@link Process#destroyForcibly()}
     *
     * @return the {@code Process} object representing the
     *         subprocess to be forcibly destroyed.
     */
    public Process destroyForcibly() {
        return wrapped.destroyForcibly();
    }

    /**
     * Closes the connection to input / output-streams
     *
     * @throws InterruptedException
     */
    public void closeStreamHandler() throws InterruptedException {
        if (streamClosed) {
            return;
        }
        TimeoutProcessCloser closer = new TimeoutProcessCloser(streams, streamCloseTimeout, TimeUnit.SECONDS);
        try {
            closer.close(wrapped);
            streamClosed = true;
        } catch (IOException e) {
            log.warn("Unable to close the streams properly", e);
        }

    }
}
