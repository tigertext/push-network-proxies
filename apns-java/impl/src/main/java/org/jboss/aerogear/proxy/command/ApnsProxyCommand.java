package org.jboss.aerogear.proxy.command;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Random;

import com.relayrides.pushy.apns.MockApnsServer;
import com.relayrides.pushy.apns.MockApnsServerBuilder;
import io.netty.channel.nio.NioEventLoopGroup;
import org.jboss.aerogear.proxy.endpoint.NotificationRegisterEndpoint;

import io.airlift.airline.Command;
import io.airlift.airline.Option;
import org.jboss.aerogear.proxy.utils.P12Util;
import org.jboss.aerogear.proxy.utils.SSLHelper;

/**
 *
 * @author <a href="mailto:miklosovic@gmail.com>Stefan Miklosovic</a>
 */
@Command(name = "apnsProxy", description = "starts APNS proxy")
public class ApnsProxyCommand extends NotificationRegisterEndpoint {

    private static final int TOKEN_LENGTH = 32;

    // simulator related

    @Option(name = "--apnsMockGatewayHost", description = "defaults to 127.0.0.1")
    private String apnsMockGatewayHost = "127.0.0.1";

    @Option(name = "--apnsMockGatewayPort", description = "defaults to 18443")
    private int apnsMockGatewayPort = 18443;

    // Certificate related

    @Option(name = "--apnsKeystore", description = "defaults to serverStore.p12 loaded from the jar")
    private String apnsKeystore;

    @Option(name = "--apnsKeystorePassword", description = "defaults to 123456")
    private String apnsKeystorePassword = "123456";

    @Option(name = "--apnsKeystoreType", description = "defaults to PKCS12")
    private String apnsKeystoreType = "PKCS12";

    @Option(name = "--apnsKeystoreAlgorithm", description = "defaults to sunx509")
    private String apnsKeystoreAlgorithm = "sunx509";

    @Option(name = "--deviceTokens", description = "must specify", required = true)
    private String deviceTokens = "";

    private String resourceServerStore = "serverStore.p12";

    private String clientSslCert = "apn_sandbox_consumer.pem";

    @Override
    public void run() {

        try {
            final KeyStore.PrivateKeyEntry privateKeyEntry = P12Util.getFirstPrivateKeyEntryFromP12InputStream(
                    getInputStream(), apnsKeystorePassword);

            final MockApnsServerBuilder serverBuilder = new MockApnsServerBuilder()
                    .setTrustedClientCertificateChain(getClientSslCert())
                    .setServerCredentials(new X509Certificate[] { (X509Certificate) privateKeyEntry.getCertificate() }, privateKeyEntry.getPrivateKey(), null)
                    .setEventLoopGroup(new NioEventLoopGroup(4));


            final MockApnsServer server = serverBuilder.build();

            String[] tokens = deviceTokens.split(",");
            for (String token : tokens) {
                server.registerDeviceTokenForTopic("com.tigertext.tigertext", token, null);
            }

            server.start(apnsMockGatewayPort).await();


        } catch (KeyStoreException | InterruptedException | IOException e) {
            e.printStackTrace();
        }

    }

    private InputStream getInputStream() {
        InputStream stream;
        try {
            File externalApnsCertificateFile = (apnsKeystore == null ? null : new File(apnsKeystore));
            if (externalApnsCertificateFile != null) {
                stream = new FileInputStream(externalApnsCertificateFile);
            } else {
                stream = SSLHelper.class.getResourceAsStream("/" + resourceServerStore);
            }
            assert stream != null;

            return stream;

        } catch (Exception ex) {
            throw new RuntimeException("Unable to build Keystore file", ex.getCause());
        }
    }

    private InputStream getClientSslCert() {
        InputStream stream;
        stream = SSLHelper.class.getResourceAsStream("/" + clientSslCert);
        if (stream == null) {
            throw new RuntimeException("Unable load client ssl cert");
        }
        return stream;
    }

}
