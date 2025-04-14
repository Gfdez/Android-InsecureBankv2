package com.android.insecurebankv2;

import android.util.Log;

/**
 * Clase para gestionar el logging de manera segura
 * Evita que información sensible se filtre a los logs
 */
public class SecureLogger {
    // Nivel de log en ambiente de producción
    private static final int PRODUCTION_LOG_LEVEL = Log.WARN;
    
    // Flag para determinar si estamos en producción o desarrollo
    private static final boolean IS_PRODUCTION = !BuildConfig.DEBUG;
    
    /**
     * Log de nivel ERROR - siempre se muestra
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     */
    public static void e(String tag, String message) {
        // Los errores siempre se loggean
        Log.e(tag, sanitizeMessage(message));
    }
    
    /**
     * Log de nivel ERROR con excepción - siempre se muestra
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     * @param throwable Excepción asociada
     */
    public static void e(String tag, String message, Throwable throwable) {
        Log.e(tag, sanitizeMessage(message), throwable);
    }
    
    /**
     * Log de nivel WARNING
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     */
    public static void w(String tag, String message) {
        // Los warnings siempre se loggean
        Log.w(tag, sanitizeMessage(message));
    }
    
    /**
     * Log de nivel INFO - no se muestra en producción
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     */
    public static void i(String tag, String message) {
        if (!IS_PRODUCTION || PRODUCTION_LOG_LEVEL <= Log.INFO) {
            Log.i(tag, sanitizeMessage(message));
        }
    }
    
    /**
     * Log de nivel DEBUG - no se muestra en producción
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     */
    public static void d(String tag, String message) {
        if (!IS_PRODUCTION || PRODUCTION_LOG_LEVEL <= Log.DEBUG) {
            Log.d(tag, sanitizeMessage(message));
        }
    }
    
    /**
     * Log de nivel VERBOSE - no se muestra en producción
     * @param tag Tag para identificar el origen
     * @param message Mensaje a loggear
     */
    public static void v(String tag, String message) {
        if (!IS_PRODUCTION || PRODUCTION_LOG_LEVEL <= Log.VERBOSE) {
            Log.v(tag, sanitizeMessage(message));
        }
    }
    
    /**
     * Log para información segura que NUNCA debe aparecer en logs
     * Solo se loggea en modo debug y con una advertencia
     * @param tag Tag para identificar el origen
     * @param message Mensaje que contiene información sensible
     */
    public static void sensitiveInfo(String tag, String message) {
        if (!IS_PRODUCTION) {
            Log.w(tag, "INFORMACIÓN SENSIBLE (solo debug): " + message);
        }
    }
    
    /**
     * Sanitiza mensajes para asegurar que no contienen información sensible
     * @param message Mensaje original
     * @return Mensaje sanitizado
     */
    private static String sanitizeMessage(String message) {
        if (message == null) {
            return "null";
        }
        
        // Sanitizar posibles passwords en el texto
        message = message.replaceAll("(?i)password\\s*[:=]\\s*[^\\s,;]*", "password=*****");
        message = message.replaceAll("(?i)contraseña\\s*[:=]\\s*[^\\s,;]*", "contraseña=*****");
        
        // Sanitizar posibles tokens
        message = message.replaceAll("(?i)token\\s*[:=]\\s*[^\\s,;]*", "token=*****");
        
        // Sanitizar posibles números de cuenta
        message = message.replaceAll("(?i)account\\s*[:=]\\s*\\d+", "account=*****");
        message = message.replaceAll("(?i)cuenta\\s*[:=]\\s*\\d+", "cuenta=*****");
        
        // Sanitizar posibles números de teléfono
        message = message.replaceAll("\\d{10,}", "**********");
        
        return message;
    }
}