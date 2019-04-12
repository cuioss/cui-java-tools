package de.icw.util.runner;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import de.icw.util.support.ObjectMethodsAsserts;

class ScriptMetadataParameterTest {

    static final String STOP_PARAMETER = "stop";

    static final String START_PARAMETER = "start";

    static final String BASE_PATH = "src/test/resources/runner/";

    static final String START_SCRIPT_WINDOWS = BASE_PATH + "startScript.bat";

    static final String STOP_SCRIPT_WINDOWS = BASE_PATH + "stopScript.bat";

    static final String START_SCRIPT_LINUX = BASE_PATH + "startScript.sh";

    static final String STOP_SCRIPT_LINUX = BASE_PATH + "stopScript.sh";

    static final ScriptMetadataParameter WINDOWS_META =
        ScriptMetadataParameter.builder().environment(Environment.WINDOWS).startScript(START_SCRIPT_WINDOWS)
                .startParameter(START_PARAMETER).stopScript(STOP_SCRIPT_WINDOWS).stopParameter(STOP_PARAMETER)
                .build();

    static final ScriptMetadataParameter LINUX_META =
        ScriptMetadataParameter.builder().environment(Environment.LINUX).startScript(START_SCRIPT_LINUX)
                .startParameter(START_PARAMETER).stopScript(STOP_SCRIPT_LINUX).stopParameter(STOP_PARAMETER)
                .build();

    @Test
    void shouldHandleFullCase() {
        ScriptMetadataParameter meta =
            ScriptMetadataParameter.builder().environment(Environment.WINDOWS).startScript(START_SCRIPT_WINDOWS)
                    .startParameter(START_PARAMETER).stopScript(STOP_SCRIPT_WINDOWS).stopParameter(STOP_PARAMETER)
                    .build();
        assertNotNull(meta.getStartScript());

    }

    @Test
    void shouldHandleOptionalStopScript() {
        ScriptMetadataParameter meta =
            ScriptMetadataParameter.builder().environment(Environment.WINDOWS).startScript(START_SCRIPT_WINDOWS)
                    .startParameter(START_PARAMETER).build();
        assertNotNull(meta.getStartScript());

    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(LINUX_META);
    }
}
