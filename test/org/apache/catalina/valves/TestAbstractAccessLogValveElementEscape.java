/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves;

import java.io.CharArrayWriter;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.AbstractAccessLogValve.AccessLogElement;

/**
 * Checks that the request URI and query string written by the %r, %q and %U access log elements are escaped so that
 * untrusted request data cannot be used to inject additional lines or fields into the access log.
 */
public class TestAbstractAccessLogValveElementEscape {

    private static final char CTRL_01 = (char) 0x01;
    private static final char A_UMLAUT = (char) 0x00e4;

    /*
     * Raw URI containing CR, LF, TAB, double quote, backslash, a control character and a non-ASCII character.
     */
    private static final String RAW_URI = "/a\nb\rc\td\"e\\k" + CTRL_01 + "g" + A_UMLAUT;
    private static final String ESCAPED_URI = "/a\\nb\\rc\\td\\\"e\\\\k\\u0001g\\u00e4";

    /*
     * Raw query string containing CR, LF, TAB, double quote, backslash and a control character.
     */
    private static final String RAW_QUERY = "q=a\nb\r\tc\"d\\e" + CTRL_01;
    private static final String ESCAPED_QUERY = "q=a\\nb\\r\\tc\\\"d\\\\e\\u0001";

    /*
     * Attempt to forge a complete, additional access log entry via the URI / query string.
     */
    private static final String FORGED_ENTRY = "\r\n127.0.0.1 - admin [01/Jan/2026:00:00:00 +0000] \"GET /admin HTTP/1.1\" 200 0";


    @Test
    public void testRequestElementEscapesUriAndQuery() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", RAW_URI, RAW_QUERY, "HTTP/1.1"));
        Assert.assertEquals("GET " + ESCAPED_URI + "?" + ESCAPED_QUERY + " HTTP/1.1", result);
        assertSafe(result);
    }


    @Test
    public void testRequestElementEscapesUri() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", RAW_URI, null, "HTTP/1.1"));
        Assert.assertEquals("GET " + ESCAPED_URI + " HTTP/1.1", result);
        assertSafe(result);
    }


    @Test
    public void testRequestElementEscapesQuery() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", "/", RAW_QUERY, "HTTP/1.1"));
        Assert.assertEquals("GET /?" + ESCAPED_QUERY + " HTTP/1.1", result);
        assertSafe(result);
    }


    @Test
    public void testRequestElementLogInjection() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", "/x" + FORGED_ENTRY, "y=1" + FORGED_ENTRY, "HTTP/1.1"));
        assertSafe(result);
        Assert.assertTrue(result, result.startsWith("GET /x\\r\\n127.0.0.1 - admin "));
        Assert.assertTrue(result, result.contains("?y=1\\r\\n127.0.0.1 - admin "));
        Assert.assertTrue(result, result.contains("\\\"GET /admin HTTP/1.1\\\""));
        Assert.assertTrue(result, result.endsWith(" HTTP/1.1"));
    }


    @Test
    public void testRequestElementPlain() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("POST", "/foo/bar", "a=1&b=2", "HTTP/1.1"));
        Assert.assertEquals("POST /foo/bar?a=1&b=2 HTTP/1.1", result);
    }


    @Test
    public void testRequestElementEmptyQuery() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", "/", "", "HTTP/1.1"));
        Assert.assertEquals("GET /? HTTP/1.1", result);
    }


    @Test
    public void testRequestElementNullQuery() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest("GET", "/", null, "HTTP/1.1"));
        Assert.assertEquals("GET / HTTP/1.1", result);
    }


    @Test
    public void testRequestElementNullMethod() {
        String result = log(new AbstractAccessLogValve.RequestElement(),
                new TesterAccessLogRequest(null, RAW_URI, RAW_QUERY, "HTTP/1.1"));
        Assert.assertEquals("-", result);
    }


    @Test
    public void testRequestElementNullRequest() {
        String result = log(new AbstractAccessLogValve.RequestElement(), null);
        Assert.assertEquals("-", result);
    }


    @Test
    public void testQueryElementEscapes() {
        String result = log(new AbstractAccessLogValve.QueryElement(),
                new TesterAccessLogRequest("GET", "/", RAW_QUERY, "HTTP/1.1"));
        Assert.assertEquals("?" + ESCAPED_QUERY, result);
        assertSafe(result);
    }


    @Test
    public void testQueryElementLogInjection() {
        String result = log(new AbstractAccessLogValve.QueryElement(),
                new TesterAccessLogRequest("GET", "/", "y=1" + FORGED_ENTRY, "HTTP/1.1"));
        Assert.assertEquals(
                "?y=1\\r\\n127.0.0.1 - admin [01/Jan/2026:00:00:00 +0000] \\\"GET /admin HTTP/1.1\\\" 200 0", result);
        assertSafe(result);
    }


    @Test
    public void testQueryElementPlain() {
        String result = log(new AbstractAccessLogValve.QueryElement(),
                new TesterAccessLogRequest("GET", "/", "a=1&b=2", "HTTP/1.1"));
        Assert.assertEquals("?a=1&b=2", result);
    }


    @Test
    public void testQueryElementEmptyQuery() {
        String result = log(new AbstractAccessLogValve.QueryElement(),
                new TesterAccessLogRequest("GET", "/", "", "HTTP/1.1"));
        Assert.assertEquals("?", result);
    }


    @Test
    public void testQueryElementNullQuery() {
        String result = log(new AbstractAccessLogValve.QueryElement(),
                new TesterAccessLogRequest("GET", "/", null, "HTTP/1.1"));
        Assert.assertEquals("", result);
    }


    @Test
    public void testQueryElementNullRequest() {
        String result = log(new AbstractAccessLogValve.QueryElement(), null);
        Assert.assertEquals("", result);
    }


    @Test
    public void testRequestURIElementEscapes() {
        String result = log(new AbstractAccessLogValve.RequestURIElement(),
                new TesterAccessLogRequest("GET", RAW_URI, RAW_QUERY, "HTTP/1.1"));
        Assert.assertEquals(ESCAPED_URI, result);
        assertSafe(result);
    }


    @Test
    public void testRequestURIElementLogInjection() {
        String result = log(new AbstractAccessLogValve.RequestURIElement(),
                new TesterAccessLogRequest("GET", "/x" + FORGED_ENTRY, null, "HTTP/1.1"));
        Assert.assertEquals(
                "/x\\r\\n127.0.0.1 - admin [01/Jan/2026:00:00:00 +0000] \\\"GET /admin HTTP/1.1\\\" 200 0", result);
        assertSafe(result);
    }


    @Test
    public void testRequestURIElementPlain() {
        String result = log(new AbstractAccessLogValve.RequestURIElement(),
                new TesterAccessLogRequest("GET", "/foo/bar", "a=1", "HTTP/1.1"));
        Assert.assertEquals("/foo/bar", result);
    }


    @Test
    public void testRequestURIElementNullRequest() {
        String result = log(new AbstractAccessLogValve.RequestURIElement(), null);
        Assert.assertEquals("-", result);
    }


    /*
     * Exercise the elements as created from a configured pattern rather than instantiated directly.
     */
    @Test
    public void testPattern() {
        AccessLogValve valve = new AccessLogValve();
        valve.setPattern("%r|%q|%U");

        TesterAccessLogRequest request = new TesterAccessLogRequest("GET", RAW_URI, RAW_QUERY, "HTTP/1.1");
        CharArrayWriter buf = new CharArrayWriter();
        Date date = new Date();
        for (AccessLogElement element : valve.logElements) {
            element.addElement(buf, date, request, null, 0);
        }
        String result = buf.toString();

        Assert.assertEquals("GET " + ESCAPED_URI + "?" + ESCAPED_QUERY + " HTTP/1.1|?" + ESCAPED_QUERY + "|" +
                ESCAPED_URI, result);
        assertSafe(result);
    }


    private static String log(AccessLogElement element, Request request) {
        CharArrayWriter buf = new CharArrayWriter();
        element.addElement(buf, new Date(), request, null, 0);
        return buf.toString();
    }


    /*
     * The logged value must only contain printable ASCII and every double quote must be escaped so that the value can
     * neither start a new log line nor terminate a quoted field early.
     */
    private static void assertSafe(String result) {
        for (int i = 0; i < result.length(); i++) {
            char c = result.charAt(i);
            Assert.assertTrue("Unescaped character [0x" + Integer.toHexString(c) + "] at index [" + i + "] in [" +
                    result + "]", c >= 32 && c < 127);
            if (c == '"') {
                Assert.assertTrue("Unescaped double quote at index [" + i + "] in [" + result + "]",
                        i > 0 && result.charAt(i - 1) == '\\');
            }
        }
    }


    private static class TesterAccessLogRequest extends Request {

        private final String method;
        private final String requestURI;
        private final String queryString;
        private final String protocol;

        TesterAccessLogRequest(String method, String requestURI, String queryString, String protocol) {
            super(null);
            this.method = method;
            this.requestURI = requestURI;
            this.queryString = queryString;
            this.protocol = protocol;
        }

        @Override
        public String getMethod() {
            return method;
        }

        @Override
        public String getRequestURI() {
            return requestURI;
        }

        @Override
        public String getQueryString() {
            return queryString;
        }

        @Override
        public String getProtocol() {
            return protocol;
        }
    }
}
