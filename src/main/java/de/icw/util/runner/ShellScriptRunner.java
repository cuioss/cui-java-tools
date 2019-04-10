package de.icw.util.runner;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.Callable;

import de.icw.util.io.MorePaths;
import de.icw.util.logging.Logger;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * {@link AbstractApplicationRunner} for running shell / bat scripts
 *
 * @author Oliver Wolff
 *
 */
@RequiredArgsConstructor
public class ShellScriptRunner extends AbstractApplicationRunner {

    private static final Logger LOG = new Logger(ShellScriptRunner.class);

    @NonNull
    @Getter
    private final ScriptMetadata scriptMetadata;

    /**
     * @param startedCheck to be passed for indicating whether a start call succeeded correctly
     * @param metadata providing the necessary meta-information
     */
    public ShellScriptRunner(Callable<Boolean> startedCheck, @NonNull ScriptMetadata metadata) {
        super(startedCheck);
        scriptMetadata = metadata;
    }

    @Override
    protected Optional<Process> doStart(Environment system) {
        Optional<ScriptMetadataParameter> meta = getMetadataForEnvironment(system);
        if (!meta.isPresent()) {
            LOG.error("No configured metadata found for '{}' in environment '{}'", getName(), system);
            return Optional.empty();
        }
        Path executable = Paths.get(meta.get().getStartScript());
        if (!MorePaths.checkExecutablePath(executable, true)) {
            LOG.error("Given path does not denote an executable script: '{}' ", executable);
            return Optional.empty();
        }
        String startScript = meta.get().getStartScriptWithParameter();
        LOG.debug("Starting script {}", startScript);
        try {
            return Optional.of(Runtime.getRuntime().exec(startScript));
        } catch (IOException e) {
            LOG.error("Unable to start script " + startScript, e);
            return Optional.empty();
        }
    }

    @Override
    protected Optional<Process> gracefulShutdown(Environment system) {
        Optional<ScriptMetadataParameter> meta = getMetadataForEnvironment(system);
        if (!meta.isPresent()) {
            LOG.warn("No configured metadata found for '{}' in environment '{}'", getName(), system);
            return Optional.empty();
        }
        if (isNullOrEmpty(meta.get().getStopScript())) {
            LOG.debug("No configured stop-script {}' in environment '{}'", getName(), system);
            return Optional.empty();
        }
        Path executable = Paths.get(meta.get().getStopScript());
        if (!MorePaths.checkExecutablePath(executable, true)) {
            LOG.error("Given path does not denote an executable script: '{}' ", executable);
            return Optional.empty();
        }
        String stopScript = meta.get().getStartScriptWithParameter();
        LOG.debug("Calling stop script {}", stopScript);
        try {
            return Optional.of(Runtime.getRuntime().exec(stopScript));
        } catch (IOException e) {
            LOG.error("Unable to call stop script " + stopScript, e);
            return Optional.empty();
        }
    }

    private Optional<ScriptMetadataParameter> getMetadataForEnvironment(Environment environment) {
        switch (environment) {
            case LINUX:
                return Optional.ofNullable(scriptMetadata.getLinuxParameter());
            case WINDOWS:
                return Optional.ofNullable(scriptMetadata.getWindowsParameter());
            case MAC_OS:
                return Optional.ofNullable(scriptMetadata.getMacOsParameter());
            default:
                return Optional.empty();
        }
    }

    private String getName() {
        return scriptMetadata.getName();
    }

}
