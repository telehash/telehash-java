package org.telehash.core;

/**
 * This is similar to the Java 7 java.nio.channels.CompletionHandler interface,
 * although this asynchronous callback interface is really just a wrapper around
 * the select/dispatch reactor pattern, so doesn't offer any proactor-like
 * scalability advantages.
 */
public interface CompletionHandler<V> {
    void completed(V result, Object attachment);
    void failed(Throwable exc, Object attachment);
}
