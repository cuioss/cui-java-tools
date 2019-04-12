package de.icw.util.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class ShellScriptRunnerTest {

    @Test
    @Disabled
    void shouldRunOsSpecificRunScript() {
        ShellScriptRunner runner = new ShellScriptRunner(ScriptMetadataTest.SCRIPT_METADATA);
        assertEquals(AbstractApplicationRunner.State.NEW, runner.getState());
        assertFalse(runner.isRunning());

        runner.start();
        assertTrue(runner.isRunning());

        runner.terminate();
    }

}
