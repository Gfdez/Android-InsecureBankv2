package com.android.insecurebankv2;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * Clase para gestionar el almacenamiento seguro de información sensible
 * Utiliza Android Keystore para proteger los datos
 */
public class SecureStorage {
    private static final String TAG = "SecureStorage";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String AES_MODE_M_OR_GREATER = "AES/GCM/NoPadding";
    private static final String AES_MODE_LESS_THAN_M = "AES/ECB/PKCS7Padding";
    private static final String KEY_ALIAS = "InsecureBankKeyAlias";
    private static final String SHARED_PREFERENCES_NAME = "SecurePrefs";

    private Context context;
    private KeyStore keyStore;

    public SecureStorage(Context context) {
        this.context = context;
        initKeystore();
    }

    /**
     * Inicializa el Android Keystore
     */
    private void initKeystore() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            // Crear clave si no existe
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateKey();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error inicializando Keystore: " + e.getMessage());
        }
    }

    /**
     * Genera una clave nueva para Android Keystore según la versión de Android
     */
    private void generateKey() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generateKeyForMOrHigher();
            } else {
                generateKeyForLowerThanM();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error generando clave: " + e.getMessage());
        }
    }

    /**
     * Genera una clave para Android M (API 23) o superior
     */
    private void generateKeyForMOrHigher() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);

        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build();

        keyGenerator.init(keySpec);
        keyGenerator.generateKey();
    }

    /**
     * Genera una clave para versiones anteriores a Android M (API 23)
     */
    private void generateKeyForLowerThanM() throws Exception {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 30);

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEY_ALIAS)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                "RSA", ANDROID_KEYSTORE);
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }

    /**
     * Cifra datos usando la clave del Keystore
     */
    private String encryptData(String data) {
        byte[] encryptedBytes = null;
        try {
            Cipher cipher;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
                cipher = Cipher.getInstance(AES_MODE_M_OR_GREATER);
                byte[] iv = new byte[12];
                new SecureRandom().nextBytes(iv);
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
                
                encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
                
                // Combinar IV y datos cifrados para almacenamiento
                byte[] combined = new byte[iv.length + encryptedBytes.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
                encryptedBytes = combined;
            } else {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
                PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
                
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                
                encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
            }
            
            return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, "Error cifrando datos: " + e.getMessage());
            return null;
        }
    }

    /**
     * Descifra datos usando la clave del Keystore
     */
    private String decryptData(String encryptedData) {
        try {
            byte[] encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT);
            
            Cipher cipher;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
                cipher = Cipher.getInstance(AES_MODE_M_OR_GREATER);
                
                // Extraer IV de los datos almacenados
                byte[] iv = new byte[12];
                byte[] ciphertext = new byte[encryptedBytes.length - 12];
                System.arraycopy(encryptedBytes, 0, iv, 0, iv.length);
                System.arraycopy(encryptedBytes, iv.length, ciphertext, 0, ciphertext.length);
                
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
                
                byte[] decryptedBytes = cipher.doFinal(ciphertext);
                return new String(decryptedBytes, "UTF-8");
            } else {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
                PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                return new String(decryptedBytes, "UTF-8");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error descifrando datos: " + e.getMessage());
            return null;
        }
    }

    /**
     * Guarda un valor de manera segura
     */
    public void saveSecureValue(String key, String value) {
        String encryptedValue = encryptData(value);
        if (encryptedValue != null) {
            SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(key, encryptedValue);
            editor.apply();
        }
    }

    /**
     * Recupera un valor almacenado de manera segura
     */
    public String getSecureValue(String key) {
        SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        String encryptedValue = prefs.getString(key, null);
        if (encryptedValue != null) {
            return decryptData(encryptedValue);
        }
        return null;
    }
    
    /**
     * Elimina un valor seguro
     */
    public void removeSecureValue(String key) {
        SharedPreferences prefs = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.remove(key);
        editor.apply();
    }
}