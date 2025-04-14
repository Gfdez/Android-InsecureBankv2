package com.android.insecurebankv2;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase para manejar el cifrado y descifrado de archivos
 * Especialmente diseñada para proteger los archivos de transacciones guardados en SD
 */
public class FileEncryption {
    private static final String TAG = "FileEncryption";
    private Context context;
    private SecureStorage secureStorage;
    private static final String FILE_KEY = "file_encryption_key";
    private static final String FILE_IV = "file_encryption_iv";

    public FileEncryption(Context context) {
        this.context = context;
        this.secureStorage = new SecureStorage(context);
        initializeKeys();
    }

    /**
     * Inicializa las claves de cifrado de archivos si no existen
     */
    private void initializeKeys() {
        if (secureStorage.getSecureValue(FILE_KEY) == null) {
            byte[] keyBytes = new byte[32]; // 256 bits
            new SecureRandom().nextBytes(keyBytes);
            String keyBase64 = Base64.encodeToString(keyBytes, Base64.DEFAULT);
            secureStorage.saveSecureValue(FILE_KEY, keyBase64);
        }

        if (secureStorage.getSecureValue(FILE_IV) == null) {
            byte[] ivBytes = new byte[16]; // 128 bits
            new SecureRandom().nextBytes(ivBytes);
            String ivBase64 = Base64.encodeToString(ivBytes, Base64.DEFAULT);
            secureStorage.saveSecureValue(FILE_IV, ivBase64);
        }
    }

    /**
     * Obtiene la clave para cifrado de archivos
     */
    private byte[] getFileKey() {
        String keyBase64 = secureStorage.getSecureValue(FILE_KEY);
        if (keyBase64 != null) {
            return Base64.decode(keyBase64, Base64.DEFAULT);
        } else {
            // Fallback seguro
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            return keyBytes;
        }
    }

    /**
     * Obtiene el IV para cifrado de archivos
     */
    private byte[] getFileIV() {
        String ivBase64 = secureStorage.getSecureValue(FILE_IV);
        if (ivBase64 != null) {
            return Base64.decode(ivBase64, Base64.DEFAULT);
        } else {
            // Fallback seguro
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            return ivBytes;
        }
    }

    /**
     * Cifra un archivo de texto
     * @param inputFilePath ruta del archivo original
     * @param outputFilePath ruta donde guardar el archivo cifrado
     * @return true si la operación tuvo éxito
     */
    public boolean encryptFile(String inputFilePath, String outputFilePath) {
        try {
            // Leer el contenido del archivo
            StringBuilder content = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(inputFilePath));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();

            // Cifrar el contenido
            byte[] keyBytes = getFileKey();
            byte[] ivBytes = getFileIV();
            
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            
            byte[] encryptedBytes = cipher.doFinal(content.toString().getBytes("UTF-8"));
            String encryptedContent = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
            
            // Escribir el contenido cifrado
            BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath));
            writer.write(encryptedContent);
            writer.close();
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error al cifrar archivo: " + e.getMessage());
            return false;
        }
    }

    /**
     * Descifra un archivo de texto
     * @param inputFilePath ruta del archivo cifrado
     * @param outputFilePath ruta donde guardar el archivo descifrado
     * @return true si la operación tuvo éxito
     */
    public boolean decryptFile(String inputFilePath, String outputFilePath) {
        try {
            // Leer el contenido cifrado
            StringBuilder encryptedContent = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(inputFilePath));
            String line;
            while ((line = reader.readLine()) != null) {
                encryptedContent.append(line);
            }
            reader.close();
            
            // Descifrar el contenido
            byte[] keyBytes = getFileKey();
            byte[] ivBytes = getFileIV();
            
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            
            byte[] encryptedBytes = Base64.decode(encryptedContent.toString(), Base64.DEFAULT);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedContent = new String(decryptedBytes, "UTF-8");
            
            // Escribir el contenido descifrado
            BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath));
            writer.write(decryptedContent);
            writer.close();
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error al descifrar archivo: " + e.getMessage());
            return false;
        }
    }

    /**
     * Escribe un contenido cifrado a un archivo
     * @param filePath ruta del archivo
     * @param content contenido que se va a cifrar y escribir
     * @return true si la operación tuvo éxito
     */
    public boolean writeEncryptedContent(String filePath, String content) {
        try {
            // Cifrar el contenido
            byte[] keyBytes = getFileKey();
            byte[] ivBytes = getFileIV();
            
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            
            byte[] encryptedBytes = cipher.doFinal(content.getBytes("UTF-8"));
            String encryptedContent = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
            
            // Escribir el contenido cifrado
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
            writer.write(encryptedContent);
            writer.close();
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error al escribir contenido cifrado: " + e.getMessage());
            return false;
        }
    }

    /**
     * Lee y descifra el contenido de un archivo
     * @param filePath ruta del archivo cifrado
     * @return contenido descifrado o null si hubo error
     */
    public String readEncryptedContent(String filePath) {
        try {
            // Leer el contenido cifrado
            StringBuilder encryptedContent = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            String line;
            while ((line = reader.readLine()) != null) {
                encryptedContent.append(line);
            }
            reader.close();
            
            // Descifrar el contenido
            byte[] keyBytes = getFileKey();
            byte[] ivBytes = getFileIV();
            
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            
            byte[] encryptedBytes = Base64.decode(encryptedContent.toString(), Base64.DEFAULT);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            Log.e(TAG, "Error al leer contenido cifrado: " + e.getMessage());
            return null;
        }
    }

    /**
     * Añade contenido cifrado a un archivo existente
     * Especialmente útil para añadir transacciones al historial
     * @param filePath ruta del archivo
     * @param additionalContent nuevo contenido a añadir (cifrado)
     * @return true si la operación tuvo éxito
     */
    public boolean appendEncryptedContent(String filePath, String additionalContent) {
        File file = new File(filePath);
        if (!file.exists()) {
            // Si el archivo no existe, simplemente escribe el contenido
            return writeEncryptedContent(filePath, additionalContent);
        }
        
        try {
            // Leer y descifrar el contenido actual
            String currentContent = readEncryptedContent(filePath);
            if (currentContent == null) {
                currentContent = "";
            }
            
            // Combinar con el nuevo contenido
            String combinedContent = currentContent + additionalContent;
            
            // Cifrar y escribir todo el contenido
            return writeEncryptedContent(filePath, combinedContent);
        } catch (Exception e) {
            Log.e(TAG, "Error al añadir contenido cifrado: " + e.getMessage());
            return false;
        }
    }
}