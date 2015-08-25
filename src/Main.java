import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;

public class Main {

    private static String passPhrase = "UGxheWVy";
    private static String initVector = "tu89geji340t89u2";

    public static void main(String[] args) {
        try {
            File file ;
            FileWriter fooWriter;
            String text = readFile(args[0], Charset.defaultCharset());
            if (Base64.isArrayByteBase64(text.getBytes())){
                file = new File(args[0]);
                fooWriter = new FileWriter(file, false);
                fooWriter.write(decrypt(text, 0));
                fooWriter.close();
            } else {
                file = new File(args[0]);
                fooWriter = new FileWriter(file, false);
                fooWriter.write(decrypt(text, 1));
                fooWriter.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
        }
    }

    private static String decrypt(String text, int args) {
        SecretKeyFactory factory = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            PBEKeySpec pbeKeySpec = null;
            try {
                pbeKeySpec = new PBEKeySpec(passPhrase.toCharArray(), initVector.getBytes("ASCII"), 1000, 384);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            Key secretKey = factory.generateSecret(pbeKeySpec);
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
            System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);

            SecretKeySpec secret = new SecretKeySpec(key, "AES");
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(initVector.getBytes());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            String data;
            switch (args){
                case 0:
                    cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
                    byte[] decodedValue = new byte[0];
                    try {
                        decodedValue = Base64.decodeBase64(text.getBytes("UTF-8"));
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    byte[] decryptedVal = cipher.doFinal(decodedValue);
                    data = new String(decryptedVal);
                    return data;
                case 1:
                    cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
                    byte[] result = new byte[0];
                    try {
                        result = cipher.doFinal(text.getBytes("UTF-8"));
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    data = Base64.encodeBase64String(result);
                    return data;
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    static String readFile(String path, Charset encoding)
            throws IOException
    {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }
}
