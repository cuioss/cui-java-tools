package de.icw.util.runner;

import static com.google.common.base.Strings.emptyToNull;
import static com.google.common.base.Strings.isNullOrEmpty;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import com.google.common.base.Joiner;

import de.icw.util.io.MorePaths;
import de.icw.util.logging.Logger;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Executes a script according to the given parameter
 *
 * @author Oliver Wolff
 *
 */
@Builder
@Value
class ShellCommandHandler {

    private static final Logger LOG = new Logger(ShellCommandHandler.class);

    @NonNull
    private String command;

    private String parameter;

    private Path directory;

    @NonNull
    private String name;

    /** Tells the used ProcessBuilder to redirect the errorStream to the default outputStream. */
    @Builder.Default
    private boolean redirectOutputStream = true;

    /**
     * @return an {@link Optional} of the created process, if could be obtained
     */
    Optional<ProcessWrapper> execute() {
        if (isNullOrEmpty(command)) {
            LOG.error("No configured command found for '{}' ", name);
            return Optional.empty();
        }
        Path executable = Paths.get(command);
        if (!MorePaths.checkExecutablePath(executable, true)) {
            LOG.error("Given path does not denote an executable script: '{}' ", executable);
            return Optional.empty();
        }
        Path workingDir = Paths.get(".");
        if (null != directory) {
            workingDir = directory;
        }
        String script = Joiner.on(' ').skipNulls().join(executable.toFile(),
                emptyToNull(parameter));
        LOG.info("Using script command '{}' in directory '{}'", script, workingDir.toAbsolutePath());
        try {
            return Optional.of(new ProcessWrapper(new ProcessBuilder(script).directory(workingDir.toFile())
                    .redirectErrorStream(redirectOutputStream).start()));
        } catch (IOException e) {
            LOG.error("Unable to start script " + script, e);
            return Optional.empty();
        }
    }
}
