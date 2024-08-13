package es.chiteroman.bootloaderspoofer;

import android.util.Log;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.LinkedList;

public record Keybox(PEMKeyPair keyPair, Certificate[] certificates) {
    public static Keybox parseKeybox(String privatekey, String... certificateStrings) {
        try {
            PEMKeyPair keyPair = parseKeyPair(privatekey);
            Certificate[] certificates = new Certificate[certificateStrings.length];
            for (int i = 0; i < certificateStrings.length; i++) {
                certificates[i] = parseCert(certificateStrings[i]);
            }
            return new Keybox(keyPair, certificates);
        } catch (Throwable t) {
            Log.e(Xposed.TAG, "Couldn't parse Keybox: " + t);
        }
        return null;
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    public KeyPair getKeyPair() {
        try {
            return new JcaPEMKeyConverter().getKeyPair(keyPair);
        } catch (Throwable t) {
            Log.e(Xposed.TAG, "Couldn't get KeyPair: " + t);
        }
        return null;
    }

    public LinkedList<Certificate> getCertificateChain() {
        return new LinkedList<>(Arrays.asList(certificates));
    }
}
