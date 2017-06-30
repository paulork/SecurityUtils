package br.com.paulork.securityutils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;

/**
 * @author Paulo R. Kraemer <paulork10@gmail.com>
 */
public class Hash {

    private static final String MD5 = "MD5";
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    
    private static final String UTF8 = "UTF-8";

    public static String toBase64(byte[] fileBytes) {
        return new String(Base64.encodeBase64(fileBytes));
    }

    public static byte[] fromBase64(String base64String) {
        return Base64.decodeBase64(base64String);
    }

    private static String hash(String info, String algoritmo, String encoding) {
        String sen = "";
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algoritmo);
            BigInteger hash = null;
            hash = new BigInteger(1, md.digest(info.getBytes(encoding)));
            sen = hash.toString(16);
            while (sen.length() < 32) {
                sen = "0" + sen;
            }
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sen;
    }

    public static String md5(String info){
        return hash(info, MD5, UTF8);
    }
    
    public static String md5(String info, String encoding){
        return hash(info, MD5, encoding);
    }
    
    public static String sha1(String info){
        return hash(info, SHA1, UTF8);
    }
    
    public static String sha1(String info, String encoding){
        return hash(info, SHA1, encoding);
    }
    
    public static String sha256(String info){
        return hash(info, SHA256, UTF8);
    }
    
    public static String sha256(String info, String encoding){
        return hash(info, SHA256, encoding);
    }
    
    public static String sha384(String info){
        return hash(info, SHA384, UTF8);
    }
    
    public static String sha384(String info, String encoding){
        return hash(info, SHA384, encoding);
    }
    
    public static String sha512(String info){
        return hash(info, SHA512, UTF8);
    }
    
    public static String sha512(String info, String encoding){
        return hash(info, SHA512, encoding);
    }
    
}
