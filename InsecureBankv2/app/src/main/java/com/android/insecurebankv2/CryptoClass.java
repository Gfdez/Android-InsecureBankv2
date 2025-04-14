package com.android.insecurebankv2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/*
La clase que gestiona el cifrado y descifrado en la aplicación
@author Dinesh Shetty (original)
@modified para mejorar la seguridad
*/
public class CryptoClass {

	private static final String TAG = "CryptoClass";
	private Context context;
	private SecureStorage secureStorage;
	private static final String IV_KEY = "encryption_iv";
	private static final String SECRET_KEY = "encryption_key";
	
	// Constructor que acepta contexto para usar SecureStorage
	public CryptoClass(Context context) {
		this.context = context;
		this.secureStorage = new SecureStorage(context);
		// Asegurar que las claves estén generadas
		initializeEncryptionKeys();
	}
	
	// Constructor sin parámetros para compatibilidad con código existente
	public CryptoClass() {
		// No hay contexto, se usará fallback seguro
	}
	
	/*
	Inicializa y almacena de forma segura las claves de cifrado si no existen
	*/
	private void initializeEncryptionKeys() {
		if (secureStorage.getSecureValue(SECRET_KEY) == null) {
			// Generar clave aleatoria para AES
			byte[] keyBytes = new byte[32]; // 256 bits
			new SecureRandom().nextBytes(keyBytes);
			String keyBase64 = Base64.encodeToString(keyBytes, Base64.DEFAULT);
			secureStorage.saveSecureValue(SECRET_KEY, keyBase64);
		}
		
		if (secureStorage.getSecureValue(IV_KEY) == null) {
			// Generar IV aleatorio
			byte[] ivBytes = new byte[16];
			new SecureRandom().nextBytes(ivBytes);
			String ivBase64 = Base64.encodeToString(ivBytes, Base64.DEFAULT);
			secureStorage.saveSecureValue(IV_KEY, ivBase64);
		}
	}
	
	/*
	Obtiene la clave segura o usa un fallback seguro
	*/
	private byte[] getSecretKey() {
		if (secureStorage != null) {
			String keyBase64 = secureStorage.getSecureValue(SECRET_KEY);
			if (keyBase64 != null) {
				return Base64.decode(keyBase64, Base64.DEFAULT);
			}
		}
		
		// Fallback para compatibilidad con código existente (más seguro que antes)
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[32];
		random.nextBytes(keyBytes);
		return keyBytes;
	}
	
	/*
	Obtiene el IV seguro o usa un fallback seguro
	*/
	private byte[] getIV() {
		if (secureStorage != null) {
			String ivBase64 = secureStorage.getSecureValue(IV_KEY);
			if (ivBase64 != null) {
				return Base64.decode(ivBase64, Base64.DEFAULT);
			}
		}
		
		// Fallback para compatibilidad con código existente (más seguro que antes)
		SecureRandom random = new SecureRandom();
		byte[] ivBytes = new byte[16];
		random.nextBytes(ivBytes);
		return ivBytes;
	}

	/*
	La función que maneja el cifrado AES-256
	ivBytes: Vector de inicialización usado por la función de cifrado
	keyBytes: Clave usada como entrada por la función de cifrado
	textBytes: Texto plano como entrada para la función de cifrado
	*/
	public static byte[] aes256encrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes)
	throws UnsupportedEncodingException,
	NoSuchAlgorithmException,
	NoSuchPaddingException,
	InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException,
	BadPaddingException {

		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = null;
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(textBytes);
	}

	/*
	La función que maneja el descifrado AES-256
	ivBytes: Vector de inicialización usado por la función de descifrado
	keyBytes: Clave usada como entrada por la función de descifrado
	textBytes: Texto cifrado como entrada para la función de descifrado
	*/
	public static byte[] aes256decrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes)
	throws UnsupportedEncodingException,
	NoSuchAlgorithmException,
	NoSuchPaddingException,
	InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException,
	BadPaddingException {

		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(textBytes);
	}

	/*
	La función que usa el descifrado AES-256
	theString: Texto cifrado como entrada para la función de descifrado
	plainText: Texto plano como salida de la operación de cifrado
	*/
	public String aesDeccryptedString(String theString) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] keyBytes = getSecretKey();
		byte[] ivBytes = getIV();
		
		try {
			byte[] cipherData = CryptoClass.aes256decrypt(ivBytes, keyBytes, Base64.decode(theString.getBytes("UTF-8"), Base64.DEFAULT));
			return new String(cipherData, "UTF-8");
		} catch (Exception e) {
			Log.e(TAG, "Error en descifrado: " + e.getMessage());
			return null;
		}
	}

	/*
	La función que usa el cifrado AES-256
	theString: Texto plano como entrada para la función de cifrado
	cipherText: Texto cifrado como salida de la operación de cifrado
	*/
	public String aesEncryptedString(String theString) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] keyBytes = getSecretKey();
		byte[] ivBytes = getIV();
		
		try {
			byte[] cipherData = CryptoClass.aes256encrypt(ivBytes, keyBytes, theString.getBytes("UTF-8"));
			return Base64.encodeToString(cipherData, Base64.DEFAULT);
		} catch (Exception e) {
			Log.e(TAG, "Error en cifrado: " + e.getMessage());
			return null;
		}
	}
}