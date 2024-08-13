package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ThreadLocalRandom;

import de.robv.android.xposed.XposedBridge;

public final class CertHack {
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private static int indexOf(byte[] array, byte[] target) {
        if (array == null || target == null || array.length == 0 || target.length == 0) {
            return -1;
        }

        outer:
        for (int i = 0; i < array.length - target.length + 1; i++) {
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }

        return -1;
    }

    public static Certificate createLeaf() throws Throwable {
        // TODO
        return null;
    }

    public static Certificate hackCertificateChainOldMethod(Certificate leaf) throws Throwable {
        JcaX509CertificateHolder holder = new JcaX509CertificateHolder((X509Certificate) leaf);

        Extension ext = holder.getExtension(OID);

        ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

        ASN1Encodable[] encodables = sequence.toArray();

        ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

        ASN1Sequence rootOfTrust = null;

        for (ASN1Encodable asn1Encodable : teeEnforced) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
            if (taggedObject.getTagNo() == 704) {
                rootOfTrust = (ASN1Sequence) taggedObject.getBaseObject().toASN1Primitive();
                break;
            }
        }

        if (rootOfTrust == null) {
            XposedBridge.log("Couldn't find RoT");
            return leaf;
        }

        byte[] certBytes = leaf.getEncoded();
        byte[] rotBytes = rootOfTrust.getEncoded();

        int index = indexOf(certBytes, rotBytes);

        if (index < 1) {
            XposedBridge.log("Index of RoT is lower than 1");
            return leaf;
        }

        int size = rootOfTrust.size();

        byte[] verifiedBootKey = new byte[32];
        ThreadLocalRandom.current().nextBytes(verifiedBootKey);

        ASN1Encodable[] rootOfTrustEnc;

        if (size == 3) {
            rootOfTrustEnc = new ASN1Encodable[]{
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0)
            };
        } else if (size == 4) {
            byte[] verifiedBootHash = new byte[32];
            ThreadLocalRandom.current().nextBytes(verifiedBootHash);
            rootOfTrustEnc = new ASN1Encodable[]{
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };
        } else {
            return leaf;
        }

        ASN1Sequence newRootOfTrust = new DERSequence(rootOfTrustEnc);

        byte[] newRotBytes = newRootOfTrust.getEncoded();

        if (rotBytes.length != newRotBytes.length) {
            XposedBridge.log("Lenght of RoT is different!");
            return leaf;
        }

        System.arraycopy(newRotBytes, 0, certBytes, index, newRotBytes.length);

        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certBytes));
    }

    public static Certificate hackLeaf(Certificate leaf) throws Throwable {
        JcaX509CertificateHolder holder = new JcaX509CertificateHolder((X509Certificate) leaf);

        // TODO

        return leaf;
    }
}
