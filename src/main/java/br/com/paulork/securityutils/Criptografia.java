package br.com.paulork.securityutils;

import br.com.paulork.securityutils.exception.SecurityUtilsException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Paulo R. Kraemer <paulork10@gmail.com>
 */
public class Criptografia {

    private KeyPairGenerator keyGen;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Cipher cipher;
    private KeyPair kp;
    private String PRIV_FILE = "private.key";
    private String PUB_FILE = "public.key";
    private static final int RSA_KEY_SIZE = 2048;//4096 - 2048 - 1024 - 512
    private static final String ALGORITMO = "RSA";

    /**
     * Inicia com o caminho (pasta) onde as chaves estão armazenadas. Caso elas
     * não existam, serão criadas.
     * 
     * @param dir_of_keys String representando o diretório que contém as chaves.
     * @throws SecurityUtilsException 
     */
    public Criptografia(String dir_of_keys) throws SecurityUtilsException {
        this(dir_of_keys == null ? null : new File(dir_of_keys));
    }
    
    /**
     * Inicia com o caminho (pasta) onde as chaves estão armazenadas. Caso elas
     * não existam, serão criadas.
     * 
     * @param dir_of_keys File apontando para o diretório que contém as chaves.
     * @throws SecurityUtilsException 
     */
    public Criptografia(File dir_of_keys) throws SecurityUtilsException {
        File pub = null;
        File priv = null;

        if (dir_of_keys != null && dir_of_keys.isDirectory() && dir_of_keys.exists()) {
            pub = new File(dir_of_keys, PUB_FILE);
            priv = new File(dir_of_keys, PRIV_FILE);
        } else {
            pub = new File(PUB_FILE);
            priv = new File(PRIV_FILE);
        }

        PUB_FILE = pub.getAbsolutePath();
        PRIV_FILE = priv.getAbsolutePath();

        try {
            cipher = Cipher.getInstance(ALGORITMO);
            if (!pub.exists() || !priv.exists()) {
                keyGen = KeyPairGenerator.getInstance(ALGORITMO);
                keyGen.initialize(RSA_KEY_SIZE);
                kp = keyGen.genKeyPair();

                publicKey = kp.getPublic();
                privateKey = kp.getPrivate();

                geraParChaves();
            } else {
                carregaChaves();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new SecurityUtilsException("Erro ao inicializar algorítmo de criptografia!", ex);
        }
    }
    
    /**
     * Inicia com o caminho completo para o arquivo com a chave pública e 
     * chave privada (a serem carregados ou criados (caso não existam)).
     * Dar preferencia a esta opção se não quiser usar o formato padrão
     * para nomes das chaves ("private.key" e "public.key").
     * 
     * @param path_to_private_key_file Caminho para o arquivo contendo a chave privada
     * @param path_to_public_key_file Caminho para o arquivo contendo a chave publica
     * @throws SecurityUtilsException 
     */
    public Criptografia(String path_to_private_key_file, String path_to_public_key_file) throws SecurityUtilsException {
        if(path_to_private_key_file == null && path_to_public_key_file == null){
            throw new SecurityUtilsException("Caminho da chave publica/privada não pode ser nulo!");
        }
        
        PUB_FILE = path_to_public_key_file;
        PRIV_FILE = path_to_private_key_file;

        try {
            cipher = Cipher.getInstance(ALGORITMO);
            if (!new File(PUB_FILE).exists() || !new File(PRIV_FILE).exists()) {
                keyGen = KeyPairGenerator.getInstance(ALGORITMO);
                keyGen.initialize(RSA_KEY_SIZE);
                kp = keyGen.genKeyPair();

                publicKey = kp.getPublic();
                privateKey = kp.getPrivate();

                geraParChaves();
            } else {
                carregaChaves();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new SecurityUtilsException("Erro ao inicializar algorítmo de criptografia!", ex);
        }
    }

    /**
     * Informar a String a ser criptografado.
     * 
     * @param criptografar Texto a ser criptografado.
     * @return String já criptografada.
     * @throws SecurityUtilsException 
     */
    public String criptografar(String criptografar) throws SecurityUtilsException {
        try {
            cipher = Cipher.getInstance(ALGORITMO);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Hash.toBase64(cipher.doFinal(criptografar.getBytes()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException ex) {
            throw new SecurityUtilsException("Erro ao criptografar!", ex);
        }
    }

    /**
     * Informar a String criptografada.
     * 
     * @param criptografado String criptografada.
     * @return String descriptografada.
     * @throws SecurityUtilsException 
     */
    public String descriptografar(String criptografado) throws SecurityUtilsException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Hash.fromBase64(criptografado)));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new SecurityUtilsException("Erro ao descriptografar!", ex);
        }
    }

    /**
     * Faz a geração do par de chaves (caso não existam).
     * 
     * @throws SecurityUtilsException 
     */
    private void geraParChaves() throws SecurityUtilsException {
        try {
            //-- Gravando a chave pública em formato serializado
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PUB_FILE));
            oos.writeObject(publicKey);
            oos.close();

            //-- Gravando a chave privada em formato serializado
            //-- Não é a melhor forma (deveria ser guardada em um keystore, e protegida por senha), 
            //-- mas isto é só um exemplo
            oos = new ObjectOutputStream(new FileOutputStream(PRIV_FILE));
            oos.writeObject(privateKey);
            oos.close();
        } catch (IOException ex) {
            throw new SecurityUtilsException("Erro ao gerar par de chaves!", ex);
        }
    }

    /**
     * Carrega o par de chave (caso existam).
     * 
     * @throws SecurityUtilsException 
     */
    private void carregaChaves() throws SecurityUtilsException {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIV_FILE));
            privateKey = (PrivateKey) ois.readObject();
            ois.close();
            ois = null;

            ois = new ObjectInputStream(new FileInputStream(PUB_FILE));
            publicKey = (PublicKey) ois.readObject();
            ois.close();
            ois = null;
        } catch (IOException | ClassNotFoundException ex) {
            throw new SecurityUtilsException("Erro ao carregar par de chaves!", ex);
        }
    }

}
