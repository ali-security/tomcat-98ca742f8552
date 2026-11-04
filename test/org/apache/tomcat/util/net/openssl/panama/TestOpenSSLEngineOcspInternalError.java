/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net.openssl.panama;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Tests that internal errors while performing an OCSP check with the FFM OpenSSLEngine (responder errors, network
 * failures, oversized or invalid responses) never leave the X509_STORE_CTX without an error and are reported with the
 * same error codes as Tomcat Native.
 * <p>
 * The test sources are compiled for Java 8 whereas the FFM code requires Java 22 so all access to the FFM API and to
 * the FFM based OpenSSL classes is via reflection.
 */
public class TestOpenSSLEngineOcspInternalError {

    private static final int OCSP_TIMEOUT_MS = 5000;
    private static final int OCSP_SHORT_TIMEOUT_MS = 1000;
    private static final int OVERSIZED_RESPONSE_LENGTH = 32 * 1024 * 1024;

    private static Class<?> memorySegmentClass;
    private static Class<?> arenaClass;
    private static Object nullSegment;
    private static Class<?> opensslH;
    private static Class<?> engineClass;
    private static Constructor<?> engineStateConstructor;
    private static Method processOCSPRequest;
    private static MethodHandle x509StoreCtxNew;
    private static MethodHandle x509StoreCtxFree;

    private static int ocspCertStatusUnknown;
    private static int errUnableToGetCrl;
    private static int errApplicationVerification;

    private static Object globalArena;
    private static Object issuer;
    private static Object x509;


    @BeforeClass
    public static void setup() throws Exception {
        Assume.assumeTrue("FFM requires Java 22 or later", JreCompat.isJre22Available());
        new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL (FFM) is not available", OpenSSLLifecycleListener.isAvailable());

        memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        arenaClass = Class.forName("java.lang.foreign.Arena");
        nullSegment = memorySegmentClass.getField("NULL").get(null);
        opensslH = Class.forName("org.apache.tomcat.util.openssl.openssl_h");

        Class<?> compatibility = Class.forName("org.apache.tomcat.util.openssl.openssl_h_Compatibility");
        Assume.assumeFalse("OCSP is not supported with BoringSSL",
                compatibility.getField("BORINGSSL").getBoolean(null));

        engineClass = Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine");
        Class<?> engineStateClass =
                Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine$EngineState");
        engineStateConstructor = engineStateClass.getDeclaredConstructor(memorySegmentClass, memorySegmentClass,
                int.class, boolean.class, int.class, int.class);
        engineStateConstructor.setAccessible(true);
        processOCSPRequest = engineClass.getDeclaredMethod("processOCSPRequest", engineStateClass, URL.class,
                memorySegmentClass, memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);

        ocspCertStatusUnknown = ((Integer) callOpenSSL("V_OCSP_CERTSTATUS_UNKNOWN")).intValue();
        errUnableToGetCrl = ((Integer) callOpenSSL("X509_V_ERR_UNABLE_TO_GET_CRL")).intValue();
        errApplicationVerification = ((Integer) callOpenSSL("X509_V_ERR_APPLICATION_VERIFICATION")).intValue();

        // X509_STORE_CTX_new and X509_STORE_CTX_free are not part of the generated API
        Method findOrThrow = opensslH.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");
        Object addressLayout = Class.forName("java.lang.foreign.ValueLayout").getField("ADDRESS").get(null);
        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Object noLayouts = Array.newInstance(memoryLayoutClass, 0);
        Object addressLayouts = Array.newInstance(memoryLayoutClass, 1);
        Array.set(addressLayouts, 0, addressLayout);
        Object noOptions = Array.newInstance(linkerOptionClass, 0);
        Object newDescriptor = functionDescriptorClass.getMethod("of", memoryLayoutClass, noLayouts.getClass())
                .invoke(null, addressLayout, noLayouts);
        Object freeDescriptor = functionDescriptorClass.getMethod("ofVoid", addressLayouts.getClass())
                .invoke(null, addressLayouts);
        Method downcallHandle = linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                noOptions.getClass());
        x509StoreCtxNew = (MethodHandle) downcallHandle.invoke(linker,
                findOrThrow.invoke(null, "X509_STORE_CTX_new"), newDescriptor, noOptions);
        x509StoreCtxFree = (MethodHandle) downcallHandle.invoke(linker,
                findOrThrow.invoke(null, "X509_STORE_CTX_free"), freeDescriptor, noOptions);

        // Load the certificate to check and its issuer
        globalArena = arenaClass.getMethod("ofShared").invoke(null);
        x509 = loadCertificate(TesterSupport.LOCALHOST_RSA_CERT_PEM);
        issuer = loadCertificate(TesterSupport.CA_CERT_PEM);
    }


    @AfterClass
    public static void cleanup() throws Exception {
        if (x509 != null) {
            callOpenSSL("X509_free", x509);
        }
        if (issuer != null) {
            callOpenSSL("X509_free", issuer);
        }
        if (globalArena != null) {
            ((AutoCloseable) globalArena).close();
        }
    }


    @Test
    public void testResponderHttpError() throws Exception {
        try (Responder responder = new Responder(new ResponseWriter() {
            @Override
            public void write(OutputStream os, Responder r) throws IOException {
                os.write(("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                os.flush();
            }
        })) {
            OcspResult result = doOcspRequest(responder.getUrl(), OCSP_TIMEOUT_MS);
            Assert.assertEquals(ocspCertStatusUnknown, result.status);
            Assert.assertEquals(errUnableToGetCrl, result.error);
        }
    }


    @Test
    public void testResponderConnectionRefused() throws Exception {
        int port;
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = serverSocket.getLocalPort();
        }
        // Nothing is listening on the port anymore
        OcspResult result = doOcspRequest(new URL("http://127.0.0.1:" + port + "/ocsp"), OCSP_TIMEOUT_MS);
        Assert.assertEquals(ocspCertStatusUnknown, result.status);
        Assert.assertEquals(errUnableToGetCrl, result.error);
    }


    @Test
    public void testResponderReadTimeout() throws Exception {
        try (Responder responder = new Responder(new ResponseWriter() {
            @Override
            public void write(OutputStream os, Responder r) throws IOException {
                // Accept the request but never answer it
                r.awaitRelease();
            }
        })) {
            OcspResult result = doOcspRequest(responder.getUrl(), OCSP_SHORT_TIMEOUT_MS);
            Assert.assertEquals(ocspCertStatusUnknown, result.status);
            Assert.assertEquals(errUnableToGetCrl, result.error);
        }
    }


    @Test
    public void testResponderOversizedResponse() throws Exception {
        final AtomicBoolean completed = new AtomicBoolean(false);
        final AtomicLong written = new AtomicLong(0);
        Responder responder = new Responder(new ResponseWriter() {
            @Override
            public void write(OutputStream os, Responder r) throws IOException {
                os.write(("HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: " +
                        OVERSIZED_RESPONSE_LENGTH + "\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                byte[] chunk = new byte[8192];
                // Start of a DER SEQUENCE so the response at least looks like it might be valid
                chunk[0] = 0x30;
                while (written.get() < OVERSIZED_RESPONSE_LENGTH) {
                    os.write(chunk);
                    written.addAndGet(chunk.length);
                    chunk[0] = 0;
                }
                os.flush();
                completed.set(true);
            }
        });
        OcspResult result;
        try {
            result = doOcspRequest(responder.getUrl(), OCSP_TIMEOUT_MS);
        } finally {
            responder.close();
        }
        Assert.assertEquals(ocspCertStatusUnknown, result.status);
        Assert.assertEquals(errUnableToGetCrl, result.error);
        // The client must have stopped reading long before the end of the response
        Assert.assertFalse("The entire oversized response (" + written.get() + " bytes) was consumed",
                completed.get());
    }


    @Test
    public void testResponderInvalidResponse() throws Exception {
        try (Responder responder = new Responder(new ResponseWriter() {
            @Override
            public void write(OutputStream os, Responder r) throws IOException {
                byte[] body = "This is not a DER encoded OCSP response".getBytes(StandardCharsets.ISO_8859_1);
                os.write(("HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: " +
                        body.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                os.write(body);
                os.flush();
            }
        })) {
            OcspResult result = doOcspRequest(responder.getUrl(), OCSP_TIMEOUT_MS);
            Assert.assertEquals(ocspCertStatusUnknown, result.status);
            Assert.assertEquals(errApplicationVerification, result.error);
        }
    }


    private static OcspResult doOcspRequest(URL url, int ocspTimeout) throws Exception {
        Object arena = arenaClass.getMethod("ofConfined").invoke(null);
        Object x509ctx = null;
        long sslAddress = 0;
        try {
            Method allocate = arenaClass.getMethod("allocate", long.class);
            // Placeholders for the SSL and BIO pointers. They are never used by the OCSP processing.
            Object ssl = allocate.invoke(globalArena, Long.valueOf(8));
            Object networkBIO = allocate.invoke(globalArena, Long.valueOf(8));
            sslAddress = ((Long) memorySegmentClass.getMethod("address").invoke(ssl)).longValue();
            Object state = engineStateConstructor.newInstance(ssl, networkBIO, Integer.valueOf(10), Boolean.FALSE,
                    Integer.valueOf(ocspTimeout), Integer.valueOf(0));

            x509ctx = invokeHandle(x509StoreCtxNew);
            Assert.assertNotEquals(nullSegment, x509ctx);
            Assert.assertEquals(0, ((Integer) callOpenSSL("X509_STORE_CTX_get_error", x509ctx)).intValue());

            int status = ((Integer) processOCSPRequest.invoke(null, state, url, issuer, x509, x509ctx, arena))
                    .intValue();
            int error = ((Integer) callOpenSSL("X509_STORE_CTX_get_error", x509ctx)).intValue();
            return new OcspResult(status, error);
        } finally {
            if (x509ctx != null) {
                invokeHandle(x509StoreCtxFree, x509ctx);
            }
            if (sslAddress != 0) {
                Field statesField = engineClass.getDeclaredField("states");
                statesField.setAccessible(true);
                ((Map<?,?>) statesField.get(null)).remove(Long.valueOf(sslAddress));
            }
            ((AutoCloseable) arena).close();
        }
    }


    private static Object loadCertificate(String path) throws Exception {
        Method allocateFrom = arenaClass.getMethod("allocateFrom", String.class);
        Object fileName = allocateFrom.invoke(globalArena, new File(path).getAbsolutePath());
        Object mode = allocateFrom.invoke(globalArena, "r");
        Object bio = callOpenSSL("BIO_new_file", fileName, mode);
        Assert.assertNotEquals(nullSegment, bio);
        try {
            Object cert = callOpenSSL("PEM_read_bio_X509_AUX", bio, nullSegment, nullSegment, nullSegment);
            Assert.assertNotEquals(nullSegment, cert);
            return cert;
        } finally {
            callOpenSSL("BIO_free", bio);
        }
    }


    private static Object invokeHandle(MethodHandle handle, Object... args) throws Exception {
        try {
            return handle.invokeWithArguments(args);
        } catch (Exception | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new Exception(t);
        }
    }


    private static Object callOpenSSL(String name, Object... args) throws Exception {
        Class<?>[] types = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) {
            types[i] = memorySegmentClass;
        }
        try {
            return opensslH.getMethod(name, types).invoke(null, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }


    private static final class OcspResult {
        private final int status;
        private final int error;

        private OcspResult(int status, int error) {
            this.status = status;
            this.error = error;
        }
    }


    private interface ResponseWriter {
        void write(OutputStream os, Responder responder) throws IOException;
    }


    /*
     * Minimal HTTP server that reads an OCSP request and then responds as instructed by the ResponseWriter.
     */
    private static final class Responder implements Closeable, Runnable {

        private final ServerSocket serverSocket;
        private final ResponseWriter responseWriter;
        private final CountDownLatch release = new CountDownLatch(1);
        private final Thread thread;

        private Responder(ResponseWriter responseWriter) throws IOException {
            this.responseWriter = responseWriter;
            serverSocket = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"));
            thread = new Thread(this, "OCSP-Responder");
            thread.setDaemon(true);
            thread.start();
        }

        private URL getUrl() throws IOException {
            return new URL("http://127.0.0.1:" + serverSocket.getLocalPort() + "/ocsp");
        }

        private void awaitRelease() {
            try {
                release.await(60, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void run() {
            while (!serverSocket.isClosed()) {
                try (Socket socket = serverSocket.accept()) {
                    readRequest(socket.getInputStream());
                    responseWriter.write(socket.getOutputStream(), this);
                } catch (IOException ioe) {
                    // Expected when the client closes the connection early or the server socket is closed
                }
            }
        }

        private static void readRequest(InputStream is) throws IOException {
            ByteArrayOutputStream headers = new ByteArrayOutputStream();
            int matched = 0;
            byte[] terminator = new byte[] { '\r', '\n', '\r', '\n' };
            while (matched < terminator.length) {
                int b = is.read();
                if (b < 0) {
                    throw new IOException("Unexpected end of request headers");
                }
                headers.write(b);
                if (b == terminator[matched]) {
                    matched++;
                } else {
                    matched = (b == terminator[0]) ? 1 : 0;
                }
            }
            long contentLength = 0;
            for (String line : new String(headers.toByteArray(), StandardCharsets.ISO_8859_1).split("\r\n")) {
                if (line.toLowerCase(Locale.ENGLISH).startsWith("content-length:")) {
                    contentLength = Long.parseLong(line.substring("content-length:".length()).trim());
                }
            }
            for (long i = 0; i < contentLength; i++) {
                if (is.read() < 0) {
                    throw new IOException("Unexpected end of request body");
                }
            }
        }

        @Override
        public void close() throws IOException {
            release.countDown();
            serverSocket.close();
            try {
                thread.join(30000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
