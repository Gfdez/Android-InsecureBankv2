package com.android.insecurebankv2;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Clase para verificar la firma de la aplicación en tiempo de ejecución
 * Esto previene la instalación de versiones modificadas/reempaquetadas de la app
 */
public class SignatureVerifier {
    private static final String TAG = "SignatureVerifier";
    
    // Esta constante debe contener el hash de la firma real de la aplicación
    // Para obtener este valor, ejecuta el método getAppSignature() una vez y almacena el resultado
    private static final String ORIGINAL_SIGNATURE_HASH = "YOUR_APP_SIGNATURE_HASH_HERE";
    
    /**
     * Verifica si la firma de la aplicación es válida
     * @param context El contexto de la aplicación
     * @return true si la firma es válida, false en caso contrario
     */
    public static boolean verifyAppSignature(Context context) {
        try {
            String currentSignature = getAppSignature(context);
            
            // Si estamos en modo debug, imprima la firma actual para configuración
            if (BuildConfig.DEBUG) {
                Log.d(TAG, "Firma actual: " + currentSignature);
                // En modo debug, permitir cualquier firma para facilitar el desarrollo
                return true;
            }
            
            // Verificar que la firma coincida con la original
            boolean isValid = ORIGINAL_SIGNATURE_HASH.equals(currentSignature);
            
            if (!isValid) {
                Log.e(TAG, "¡Verificación de firma falló! Posible aplicación manipulada.");
            }
            
            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "Error verificando firma: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Obtiene el hash de la firma de la aplicación instalada
     * @param context El contexto de la aplicación
     * @return El hash SHA-256 de la firma
     */
    public static String getAppSignature(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            
            // Obtener la primera firma (normalmente solo hay una)
            Signature signature = packageInfo.signatures[0];
            
            // Calcular hash SHA-256 de la firma
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(signature.toByteArray());
            byte[] digest = md.digest();
            
            // Convertir el hash a un string hexadecimal
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
            
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Error obteniendo firma: " + e.getMessage());
            return "";
        }
    }
    
    /**
     * Detecta si la aplicación está siendo ejecutada en un entorno potencialmente inseguro
     * @param context El contexto de la aplicación
     * @return true si el entorno es seguro, false si es inseguro
     */
    public static boolean isSecureEnvironment(Context context) {
        // Verificar la firma de la aplicación
        if (!verifyAppSignature(context)) {
            return false;
        }
        
        // Verificar si el dispositivo está rooteado (podría mejorar con más verificaciones)
        if (isDeviceRooted()) {
            Log.w(TAG, "Dispositivo tiene acceso root");
            // Podríamos decidir permitir dispositivos rooteados o no
            // return false;
        }
        
        // Verificar si estamos en un emulador
        if (isEmulator()) {
            Log.w(TAG, "Aplicación ejecutándose en un emulador");
            // Podríamos decidir permitir emuladores o no
            // return false;
        }
        
        // Todo bien
        return true;
    }
    
    /**
     * Verifica si el dispositivo está rooteado
     * @return true si el dispositivo está rooteado
     */
    private static boolean isDeviceRooted() {
        // Comprobar archivos comunes que existen en dispositivos rooteados
        String[] rootFiles = {
                "/system/app/Superuser.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/system/su",
                "/system/bin/.ext/.su"
        };
        
        for (String file : rootFiles) {
            if (new java.io.File(file).exists()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detecta si la aplicación está corriendo en un emulador
     * @return true si es un emulador
     */
    private static boolean isEmulator() {
        return android.os.Build.FINGERPRINT.startsWith("generic")
                || android.os.Build.FINGERPRINT.startsWith("unknown")
                || android.os.Build.MODEL.contains("google_sdk")
                || android.os.Build.MODEL.contains("Emulator")
                || android.os.Build.MODEL.contains("Android SDK built for x86")
                || android.os.Build.MANUFACTURER.contains("Genymotion")
                || (android.os.Build.BRAND.startsWith("generic") && android.os.Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(android.os.Build.PRODUCT);
    }
}