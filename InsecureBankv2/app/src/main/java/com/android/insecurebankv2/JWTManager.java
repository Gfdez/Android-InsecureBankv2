package com.android.insecurebankv2;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

/**
 * Clase que gestiona la autenticación mediante tokens JWT
 * Permite reducir el envío repetido de credenciales en cada petición HTTP
 */
public class JWTManager {
    private static final String TAG = "JWTManager";
    private static final String PREF_NAME = "JWTPrefs";
    private static final String JWT_TOKEN_KEY = "jwt_token";
    private static final long TOKEN_EXPIRATION = TimeUnit.HOURS.toMillis(1); // 1 hora de validez
    
    // Clave secreta para firmar los tokens (en un entorno real debe estar protegida)
    private static final SecretKey JWT_SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    
    private Context context;
    
    public JWTManager(Context context) {
        this.context = context;
    }
    
    /**
     * Genera un nuevo token JWT para un usuario
     */
    public String generateToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + TOKEN_EXPIRATION);
        
        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(JWT_SECRET_KEY)
                .compact();
                
        // Guardar el token en las preferencias
        saveToken(token);
        
        return token;
    }
    
    /**
     * Valida un token JWT y extrae el username
     */
    public String validateTokenAndGetUsername(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(JWT_SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
                    
            return claims.getSubject();
        } catch (ExpiredJwtException e) {
            Log.e(TAG, "JWT token ha expirado");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error validando JWT token: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Guarda el token en SharedPreferences
     */
    private void saveToken(String token) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(JWT_TOKEN_KEY, token);
        editor.apply();
    }
    
    /**
     * Recupera el token JWT guardado
     */
    public String getToken() {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(JWT_TOKEN_KEY, null);
    }
    
    /**
     * Comprueba si hay un token válido almacenado
     */
    public boolean hasValidToken() {
        String token = getToken();
        if (token == null) {
            return false;
        }
        
        String username = validateTokenAndGetUsername(token);
        return username != null;
    }
    
    /**
     * Elimina el token guardado (logout)
     */
    public void clearToken() {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.remove(JWT_TOKEN_KEY);
        editor.apply();
    }
}