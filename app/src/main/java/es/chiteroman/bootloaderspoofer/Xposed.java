package es.chiteroman.bootloaderspoofer;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.LinkedList;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    public static final String TAG = "BootloaderSpoofer";
    private static final Keybox EC, RSA;
    public static boolean hackCertificateChainOldMethod = false;
    private static byte[] attestationChallengeBytes = new byte[0];

    static {
        try {
            EC = Keybox.parseKeybox(
                    KeyboxData.EC.PRIVATE_KEY,
                    KeyboxData.EC.CERTIFICATE_1,
                    KeyboxData.EC.CERTIFICATE_2
            );
            RSA = Keybox.parseKeybox(
                    KeyboxData.RSA.PRIVATE_KEY,
                    KeyboxData.RSA.CERTIFICATE_1,
                    KeyboxData.RSA.CERTIFICATE_2
            );
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.isFirstApplication) return;

        final var systemFeatureHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String featureName = (String) param.args[0];

                if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(featureName))
                    param.setResult(Boolean.FALSE);
                else if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(featureName))
                    param.setResult(Boolean.FALSE);
                else if ("android.software.device_id_attestation".equals(featureName))
                    param.setResult(Boolean.FALSE);
            }
        };

        try {
            Application app = AndroidAppHelper.currentApplication();

            Class<?> PackageManagerClass;

            if (app == null) {
                PackageManagerClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", lpparam.classLoader);
            } else {
                PackageManagerClass = app.getPackageManager().getClass();
            }

            XposedHelpers.findAndHookMethod(PackageManagerClass, "hasSystemFeature", String.class, systemFeatureHook);
            XposedHelpers.findAndHookMethod(PackageManagerClass, "hasSystemFeature", String.class, int.class, systemFeatureHook);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }

        try {
            XposedHelpers.findAndHookMethod(KeyGenParameterSpec.Builder.class, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    attestationChallengeBytes = (byte[]) param.args[0];
                }
            });
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }

        try {
            KeyPairGeneratorSpi keyPairGeneratorSpi_EC = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGeneratorSpi_EC.getClass(), "generateKeyPair", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return EC.getKeyPair();
                }
            });
            KeyPairGeneratorSpi keyPairGeneratorSpi_RSA = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGeneratorSpi_RSA.getClass(), "generateKeyPair", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return RSA.getKeyPair();
                }
            });
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Certificate[] caList = null;

                    try {
                        caList = (Certificate[]) param.getResultOrThrowable();
                    } catch (Throwable t) {
                        Log.e(TAG, t.toString());
                    }

                    if (caList == null) {

                        Certificate leaf = null;

                        try {
                            leaf = CertHack.createLeaf();
                        } catch (Throwable t) {
                            Log.e(TAG, t.toString());
                        }

                        if (leaf == null) return;

                        LinkedList<Certificate> certs = EC.getCertificateChain();

                        certs.addFirst(leaf);

                        caList = certs.toArray(new Certificate[0]);

                    } else {
                        if (hackCertificateChainOldMethod) {
                            try {
                                caList[0] = CertHack.hackCertificateChainOldMethod(caList[0]);
                            } catch (Throwable t) {
                                Log.e(TAG, t.toString());
                            }

                            for (Method declaredMethod : caList[0].getClass().getDeclaredMethods()) {
                                if (declaredMethod.getName().toLowerCase().contains("verify") ||
                                        declaredMethod.getName().toLowerCase().contains("check")) {
                                    XposedBridge.hookMethod(declaredMethod, XC_MethodReplacement.DO_NOTHING);
                                }
                            }
                        } else {
                            Certificate leaf = null;

                            try {
                                leaf = CertHack.hackLeaf(caList[0]);
                            } catch (Throwable t) {
                                Log.e(TAG, t.toString());
                            }

                            if (leaf == null) return;

                            boolean isEC = KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm());

                            LinkedList<Certificate> certs = isEC ? EC.getCertificateChain() : RSA.getCertificateChain();

                            certs.addFirst(leaf);

                            caList = certs.toArray(new Certificate[0]);
                        }
                    }

                    param.setResult(caList);
                }
            });
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
    }
}
