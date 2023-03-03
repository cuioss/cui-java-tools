package de.cuioss.tools.io.support;

import java.io.IOException;
import java.io.InputStream;

import org.opentest4j.AssertionFailedError;

/**
 * Helper class for checking behaviour of IO classes.
 *
 * @author https://github.com/apache/commons-io/blob/master/src/test/java/org/apache/commons/io/testtools/YellOnCloseInputStream.java
 */
public class YellOnCloseInputStream extends ProxyInputStream {

    /**
     * @param proxy InputStream to delegate to.
     */
    public YellOnCloseInputStream(final InputStream proxy) {
        super(proxy);
    }

    /** @see java.io.InputStream#close() */
    @Override
    public void close() throws IOException {
        throw new AssertionFailedError("close() was called on OutputStream");
    }
}
