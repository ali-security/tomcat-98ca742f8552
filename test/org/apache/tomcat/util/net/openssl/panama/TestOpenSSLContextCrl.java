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

import java.io.File;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Tests that an error loading the configured certificate revocation list(s) prevents the FFM OpenSSL connector from
 * starting, as it does for the other TLS implementations, rather than being logged and ignored which would allow
 * revoked certificates to be accepted.
 * <p>
 * The test sources are compiled for Java 8 whereas the FFM code requires Java 22 so the FFM based implementation is
 * only referenced by name.
 */
public class TestOpenSSLContextCrl extends TomcatBaseTest {

    private static final String SSL_IMPLEMENTATION_NAME =
            "org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation";


    @Test
    public void testNoCertificateRevocationList() throws Exception {
        // Ensure the configuration used by the other tests is otherwise valid
        Tomcat tomcat = getTomcatInstance();
        configureSsl(tomcat);

        tomcat.start();
    }


    @Test
    public void testInvalidCertificateRevocationListFile() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        SSLHostConfig sslHostConfig = configureSsl(tomcat);
        // The file exists but does not contain a CRL
        String crlFile = new File(TesterSupport.JKS_KEY_PASS_FILE).getAbsolutePath();
        sslHostConfig.setCertificateRevocationListFile(crlFile);

        doTestStartFails(tomcat, crlFile);
    }


    @Test
    public void testInvalidCertificateRevocationListPath() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        SSLHostConfig sslHostConfig = configureSsl(tomcat);
        // OpenSSL rejects an empty directory name
        sslHostConfig.setCertificateRevocationListPath("");

        doTestStartFails(tomcat, null);
    }


    private SSLHostConfig configureSsl(Tomcat tomcat) {
        Connector connector = tomcat.getConnector();
        connector.setPort(0);
        connector.setScheme("https");
        connector.setSecure(true);
        Assert.assertTrue(connector.setProperty("SSLEnabled", "true"));

        // PEM configuration with no trust store so the CRLs are loaded by OpenSSL
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.RSA);
        certificate.setCertificateFile(new File(TesterSupport.LOCALHOST_RSA_CERT_PEM).getAbsolutePath());
        certificate.setCertificateKeyFile(new File(TesterSupport.LOCALHOST_RSA_KEY_PEM).getAbsolutePath());
        sslHostConfig.addCertificate(certificate);
        sslHostConfig.setCaCertificateFile(new File(TesterSupport.CA_CERT_PEM).getAbsolutePath());
        sslHostConfig.setCertificateVerification("required");
        connector.addSslHostConfig(sslHostConfig);

        TesterSupport.configureSSLImplementation(tomcat, SSL_IMPLEMENTATION_NAME, true);

        return sslHostConfig;
    }


    private void doTestStartFails(Tomcat tomcat, String expectedInMessage) throws Exception {
        try {
            tomcat.start();
            Assert.fail("The connector started with an invalid certificate revocation list configuration");
        } catch (LifecycleException e) {
            // Expected. Make sure the failure was caused by the CRL configuration.
            Throwable rootCause = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            Assert.assertTrue(rootCause.toString(), rootCause instanceof IllegalArgumentException);
            if (expectedInMessage != null) {
                Assert.assertTrue(rootCause.getMessage(), rootCause.getMessage().contains(expectedInMessage));
            }
        }
    }
}
