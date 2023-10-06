/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.io.support;

import java.io.IOException;
import java.io.OutputStream;

import org.opentest4j.AssertionFailedError;

/**
 * Helper class for checking behaviour of IO classes.
 *
 * @author https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/testtools/YellOnFlushAndCloseOutputStream.java
 *
 */
public class YellOnFlushAndCloseOutputStream extends ProxyOutputStream {

    private boolean yellForFlush;
    private boolean yellForClose;

    /**
     * @param proxy        OutputStream to delegate to.
     * @param yellForFlush True if flush() is forbidden
     * @param yellForClose True if close() is forbidden
     */
    public YellOnFlushAndCloseOutputStream(final OutputStream proxy, final boolean yellForFlush,
            final boolean yellForClose) {
        super(proxy);
        this.yellForFlush = yellForFlush;
        this.yellForClose = yellForClose;
    }

    /** @see java.io.OutputStream#flush() */
    @Override
    public void flush() throws IOException {
        if (yellForFlush) {
            throw new AssertionFailedError("flush() was called on OutputStream");
        }
        super.flush();
    }

    /** @see java.io.OutputStream#close() */
    @Override
    public void close() throws IOException {
        if (yellForClose) {
            throw new AssertionFailedError("close() was called on OutputStream");
        }
        super.close();
    }

    public void off() {
        yellForFlush = false;
        yellForClose = false;
    }

}
