package de.icw.util.runner;

import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;
import static de.icw.util.runner.ScriptMetadataTest.SCRIPT_METADATA;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

class ShellCommandHandlerTest {

    @Test
    void shouldExecuteExisitingScript() {
        ScriptMetadataParameter meta = getMetadataForEnvironment().get();

        ShellCommandHandler handler =
            ShellCommandHandler.builder().command(meta.getStartScript()).name("start-script").build();

        Optional<ProcessWrapper> execute = handler.execute();
        assertTrue(execute.isPresent());
        ProcessWrapper wrapper = execute.get();
        sleepUninterruptibly(1, TimeUnit.SECONDS);
        wrapper.getStreams().flush();

        System.out.println(wrapper.getConsoleContent());

        wrapper.sendCommand("Y\n");
        wrapper.getStreams().flush();
        System.out.println(wrapper.getConsoleContent());
        sleepUninterruptibly(1, TimeUnit.SECONDS);
        wrapper.destroy();

        System.out.println(wrapper.getConsoleContent());
        // wrapper.closeStreamHandler();
    }

    private Optional<ScriptMetadataParameter> getMetadataForEnvironment() {
        switch (Environment.determineEnviromnent()) {
            case LINUX:
                return Optional.ofNullable(SCRIPT_METADATA.getLinuxParameter());
            case WINDOWS:
                return Optional.ofNullable(SCRIPT_METADATA.getWindowsParameter());
            default:
                return Optional.empty();
        }
    }
}
