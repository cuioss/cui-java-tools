package de.icw.util.runner;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.util.Optional;
import java.util.concurrent.Callable;

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
    protected Optional<ProcessWrapper> doStart(Environment system) {
        Optional<ScriptMetadataParameter> meta = getMetadataForEnvironment(system);
        if (!meta.isPresent()) {
            LOG.error("No configured metadata found for '{}' in environment '{}'", scriptMetadata.getName(), system);
            return Optional.empty();
        }
        ScriptMetadataParameter parameter = meta.get();
        return ShellCommandHandler.builder().command(parameter.getStartScript()).name(getScriptMetadata().getName())
                .parameter(parameter.getStartParameter()).build().execute();
    }

    @Override
    protected Optional<ProcessWrapper> gracefulShutdown(Environment system) {
        Optional<ScriptMetadataParameter> meta = getMetadataForEnvironment(system);
        if (!meta.isPresent()) {
            LOG.warn("No configured metadata found for '{}' in environment '{}'", scriptMetadata.getName(), system);
            return Optional.empty();
        }
        if (isNullOrEmpty(meta.get().getStopScript())) {
            LOG.debug("No configured stop-script {}' in environment '{}'", scriptMetadata.getName(), system);
            return Optional.empty();
        }
        ScriptMetadataParameter parameter = meta.get();
        return ShellCommandHandler.builder().command(parameter.getStopScript()).name(getScriptMetadata().getName())
                .parameter(parameter.getStopParameter()).build().execute();
    }

    private Optional<ScriptMetadataParameter> getMetadataForEnvironment(Environment environment) {
        switch (environment) {
            case LINUX:
                return Optional.ofNullable(scriptMetadata.getLinuxParameter());
            case WINDOWS:
                return Optional.ofNullable(scriptMetadata.getWindowsParameter());
            default:
                return Optional.empty();
        }
    }

}
