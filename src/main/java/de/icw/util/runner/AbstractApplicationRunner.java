package de.icw.util.runner;

import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;

import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Stopwatch;

import de.icw.util.logging.Logger;
import lombok.Getter;

/**
 * Wraps an application / script in order to be started / stopped in context of an unit-test.
 *
 * @author Oliver Wolff
 *
 */
public abstract class AbstractApplicationRunner {

    private static final Logger LOG = new Logger(AbstractApplicationRunner.class);

    @Getter
    private Optional<ProcessWrapper> process = Optional.empty();

    /** the current {@link State} of the service. */
    @Getter
    private State state = State.NEW;

    private final Environment environment = Environment.determineEnviromnent();

    private final Callable<Boolean> startedCheck;

    /**
     * @param startedCheck to be passed for indicating whether a start call succeeded correctly
     */
    public AbstractApplicationRunner(Callable<Boolean> startedCheck) {
        this.startedCheck = startedCheck;
    }

    /**
     * Default constructor setting a check for existence of the {@link Process} and whether
     * {@link Process#isAlive()} as startedCheck
     */
    public AbstractApplicationRunner() {
        startedCheck = () -> process.isPresent() && process.get().isAlive();
    }

    /**
     * Starts the contained application
     */
    public void start() {
        Stopwatch stopWatch = Stopwatch.createStarted();
        LOG.debug("Starting script '{}'", getName());
        state = State.STARTING;
        process = doStart(environment);
        boolean isRunning = checkProcessIsUpAndRunning();
        stopWatch.stop();
        if (process.isPresent() && isRunning) {
            LOG.info("Successfully started script '{}', took {} seconds", getName(),
                    stopWatch.elapsed(TimeUnit.SECONDS));
            state = State.RUNNING;
        } else {
            LOG.error("Unable to start '{}', took {} seconds", getName(), stopWatch.elapsed(TimeUnit.SECONDS));
            state = State.FAILED;
        }
    }

    /**
     * Stops / terminates the contained application
     */
    public void terminate() {
        Stopwatch stopWatch = Stopwatch.createStarted();
        LOG.debug("Terminating process '{}'", getName());
        if (!process.isPresent()) {
            LOG.error("No process found, therefore unable to terminate '{}'", getName());
            return;
        }
        LOG.info("Terminating process '{}', '{}'", getName(), process);
        state = State.STOPPING;
        Optional<ProcessWrapper> shutdownProcess = gracefulShutdown(environment);

        if (shutdownProcess.isPresent()) {
            LOG.info("Waiting for shutdown-process to complete {}", getName());
            shutdownProcess(shutdownProcess.get());
        }
        if (!process.isPresent() || !process.get().isAlive()) {
            stopWatch.stop();
            LOG.info("Process '{}' terminated, took {} seconds", getName(), stopWatch.elapsed(TimeUnit.SECONDS));
            process = Optional.empty();
            state = State.TERMINATED;
            return;
        }
        shutdownProcess(process.get());
        if (!process.isPresent() || !process.get().isAlive()) {
            stopWatch.stop();
            LOG.info("Process '{}' terminated, took {} seconds", getName(), stopWatch.elapsed(TimeUnit.SECONDS));
            process = Optional.empty();
            state = State.TERMINATED;
            return;
        }
        LOG.error("Unable to terminate Process '{}', took {} seconds", getName(),
                stopWatch.elapsed(TimeUnit.SECONDS));
    }

    /**
     * @param proc
     */
    private void shutdownProcess(ProcessWrapper proc) {
        if (proc != null) {
            proc.destroy();
            try {
                proc.waitFor(getScriptMetadata().getShutdownTimeout(), TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.debug("Process destroy was interrupted for " + getName(), e);
            }
            if (proc.isAlive()) {
                proc.destroyForcibly();
            }
        }

    }

    private boolean checkProcessIsUpAndRunning() {
        boolean isUp = false;
        for (int i = 0; i < getScriptMetadata().getStartCheckCount() && !isUp; ++i) {
            try {
                isUp = startedCheck.call();
            } catch (Exception e) {
                // ignore, this might be the only chance to tell that it is not running...
            }
            if (!isUp) {
                sleepUninterruptibly(getScriptMetadata().getStartCheckTimeout(), TimeUnit.SECONDS);
            }
        }
        return isUp;
    }

    /** @return {@code true} if this service is {@linkplain State#RUNNING running}. */
    public boolean isRunning() {
        return State.RUNNING.equals(getState());
    }

    /**
     * @return the 'logical' name of the script / application, e.g. iam-server-tanuki
     */
    private String getName() {
        return getScriptMetadata().getName();
    }

    /**
     * @return the {@link ScriptMetadata} for the conrete
     */
    protected abstract ScriptMetadata getScriptMetadata();

    /**
     * The synchronous starting of the the Script. It is not expected to wait until script has
     * started, just to pass the / script / command to the runtime.
     *
     * @param system
     *
     * @return The {@link ProcessWrapper} object
     */
    protected abstract Optional<ProcessWrapper> doStart(Environment system);

    /**
     * The synchronous termination of the the Script. This is an optional operation. The
     * implementation usually calls a shutdown script.
     *
     * @param system identifying the system
     * @return An {@link Optional} on the {@link ProcessWrapper} that represents the
     *         <em>shutdown</em> script / process
     *
     */
    protected Optional<ProcessWrapper> gracefulShutdown(Environment system) {
        // default is noop
        return Optional.empty();
    }

    /**
     * The lifecycle states of a service. Inspired by
     * com.google.common.util.concurrent.Service.State
     *
     */
    public enum State {

        /**
         * A service in this state is inactive.
         */
        NEW,

        /** A service in this state is transitioning to {@link #RUNNING}. */
        STARTING,

        /** A service in this state is operational. */
        RUNNING,

        /** A service in this state is transitioning to {@link #TERMINATED}. */
        STOPPING,

        /** A service in this state has completed execution normally. */
        TERMINATED,

        /**
         * A service in this state has encountered a problem and may not be operational. It cannot
         * be started nor stopped.
         */
        FAILED;

    }
}
