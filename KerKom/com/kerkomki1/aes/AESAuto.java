package com.kerkomki1.aes;

import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AESAuto {
    private static final String ALGORITHM = "AES";
    private byte[] keyValue;

    public AESAuto(String key) {
        keyValue = key.getBytes();
    }

    public String encrypt(String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = Base64.getEncoder().encodeToString(encVal);
        return encryptedValue;
    }
    public String encryptToHex(String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = bytesToHex(encVal);
        return encryptedValue;
    }

    public String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    private byte[] hexToBytes(String encryptedData) {
        int len = encryptedData.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(encryptedData.charAt(i), 16) << 4)
                    + Character.digit(encryptedData.charAt(i+1), 16));
        }
        return data;
    }

    private Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGORITHM);
        return key;
    }

    private static String cipher(String key, String text, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(mode, secretKeySpec);
        byte[] result = cipher.doFinal(text.getBytes());
        return new String(result);
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("Masukkan teks: ");
        String data = sc.nextLine();

        System.out.println("Masukkan key: ");
        String key = sc.nextLine();
        AESAuto aes = new AESAuto(key);

        String encrypted = aes.encrypt(data);
        String decrypted = aes.decrypt(encrypted);
        String ciphered = cipher(key, data, Cipher.ENCRYPT_MODE);
        System.out.println("\nText: " + data + " ----- size: " + data.length() + " bytes");
        System.out.println("Key: " + key + " ----- size: " + key.length() + " bytes");
        System.out.println("Encrypted Text: " + encrypted + " ----- size: " + encrypted.length() + " bytes");
        System.out.println("HEX Encrypted Text: " + aes.encryptToHex(data) + " ----- size: " + aes.encryptToHex(data).length() + " bytes");
        System.out.println("Decrypted Text: " + decrypted + " ----- size: " + decrypted.length() + " bytes");


    }

}
