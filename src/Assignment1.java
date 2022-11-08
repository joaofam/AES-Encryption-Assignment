import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Assignment1
{
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        // provided values
        // all with a base of 16 https://stackoverflow.com/questions/11918123/how-to-convert-biginteger-value-to-hex-in-java

        // prime modulus p
        BigInteger primeModulus = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        // generator g
        BigInteger generator = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        // public shared value A
        BigInteger publicSharedValue = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

        // https://stackoverflow.com/questions/64721974/generating-n-random-bits-in-java
        //secret value b
        BigInteger secretValue = new BigInteger(1023, new SecureRandom());
        
        // public shared value B given by gb (mod p) https://danielmiessler.com/study/diffiehellman/
        BigInteger publicValue = modularExp(generator, secretValue, primeModulus);

        // shared secret s given by Ab (mod p)
        BigInteger sharedSecret = modularExp(publicSharedValue, secretValue, primeModulus);
        
        IvParameterSpec iv = getIV();

        SecretKeySpec k = get256AESKey(sharedSecret);

        // write secretValue to DH.txt
        // https://www.baeldung.com/java-write-to-file
        BufferedWriter writer = new BufferedWriter(new FileWriter("DH.txt"));
        // https://www.baeldung.com/java-byte-arrays-hex-strings
        writer.write(publicValue.toString(16));
        writer.close();

        // write IV to IV.txt
        // BigInteger Iv_output = new BigInteger(iv, 16);
        BufferedWriter writer2 = new BufferedWriter(new FileWriter("IV.txt"));
        writer2.write(byteArrayToHex(iv.getIV()));
        writer2.close();

        BufferedWriter writer3 = new BufferedWriter(new FileWriter("key.txt"));
        writer3.write(k.toString());
        writer3.close();

        // https://stackoverflow.com/questions/1055318/using-command-line-argument-for-passing-files-to-a-program
        File file = new File(args[0]);

        int fileSize = getFileBytes(file);
        
        int paddingLen = getPaddingLen(fileSize);
        
        byte[] fileBytes = Files.readAllBytes(Paths.get(args[0]));

        byte[] paddedBytes = pad(fileSize, paddingLen, fileBytes);

        // System.out.println(new BigInteger(1, paddedBytes).toString(16));
        encrypt(k, iv, paddedBytes);

        byte[] encryptionResult = encrypt(k, iv, paddedBytes);

        System.out.print((byteArrayToHex(encryptionResult)));
    }
    
    // function to perform modular exponentiation 
    private static BigInteger modularExp(BigInteger a, BigInteger x, BigInteger n)
    {
        // Taken from https://loop.dcu.ie/mod/resource/view.php?id=1880895
        // left to right y=a^*(mod n)
        // Initialize y object
        BigInteger y = new BigInteger("1");
        int k = x.bitLength();
        
        for(int i = k-1; i >= 0; i--)
        {
            y = y.multiply(y).mod(n);
            if(x.testBit(i))
            {
                y = y.multiply(a).mod(n);
            }
        }
        return y;
    }

    // Conver bytes to hexadecimal
    // https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    private static String byteArrayToHex(byte[] byteArray) {
        StringBuilder string = new StringBuilder(byteArray.length * 2);
        for(byte b: byteArray)
           string.append(String.format("%02x", b));
        return string.toString();
    }

    // function to convert BigInteger to byte array with aid of https://stackoverflow.com/questions/4407779/biginteger-to-byte
    private static byte[] bigIntegerToBytes(BigInteger key)
    {
        byte[] array = key.toByteArray();
        if (array[0] == 0) 
        {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array;
    }
     
     // Encryption with aid og https://www.youtube.com/watch?v=rnubKjspSdQ&t=303s
    private static byte[] encrypt(SecretKeySpec secretKey, IvParameterSpec iv, byte[] fileData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] encryptionBytes = null;
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        encryptionBytes = cipher.doFinal(fileData);
        return encryptionBytes;
        
    }

    // function to calculate size of bytes in file
    private static int getFileBytes(File filename)
    {
        // get length of bytes https://stackoverflow.com/questions/14478968/get-total-size-of-file-in-bytes
        int fileLen = (int) filename.length();
        return fileLen;
    }

    // function to calculate necessary padding 
    private static int getPaddingLen(int fileLen)
    {
        int paddingLen = 16 - (fileLen % 16);
        return paddingLen;
    }

    // function to create correct pad
    private static byte[] pad(int fileLen, int paddingLen, byte[] filebytes)
    {
        int len = paddingLen + fileLen;
        
        byte[] pad = new byte[len];
        System.arraycopy(filebytes, 0,pad, 0, filebytes.length);

        pad[fileLen] = (byte) 128;
        for (int i = 1; i < paddingLen; i++) {
            pad[fileLen + i] = (byte) 0;
        }
        return pad;
    }

    // function to generate the 256 AES key
    private static SecretKeySpec get256AESKey(BigInteger key) throws NoSuchAlgorithmException
    {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            // Digest and create new allocated byte array 
            // https://www.geeksforgeeks.org/biginteger-class-in-java/
            byte[] hash = messageDigest.digest(bigIntegerToBytes(key));
            // From crypto library, specifies for AES algorithim
            return new SecretKeySpec(hash, "AES");
    }

    // your 128-bit IV in hexadecimal (32 hex digits with no white space).
    private static IvParameterSpec getIV()
    {
        SecureRandom random = new SecureRandom();
        // generate IV of 16 bytes - 128-bit = 16 characters
        byte[] iv = new byte[ 16 ];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}

/* SOURCES - all sources used in aid to create all components within assignment requirements
IV Generation - https://www.baeldung.com/java-encryption-iv
                https://stackoverflow.com/questions/56964893/how-to-create-random-aes-128-privatekey-and-iv-as-strings
Modular Exponentiation - https://loop.dcu.ie/mod/resource/view.php?id=1880895
                         https://danielmiessler.com/study/diffiehellman/
                         bitLength() - https://www.l3harrisgeospatial.com/docs/biginteger.html#:~:text=The%20BigInteger%20class%20stores%20a,the%20end%20of%20the%20array.
                         https://www.youtube.com/watch?v=czk4TXk_fvIBigInteger - https://www.baeldung.com/java-biginteger
BigInteger- https://www.javatpoint.com/java-biginteger
            https://www.geeksforgeeks.org/biginteger-class-in-java/
            https://www.youtube.com/watch?v=QBirgriSKus
            https://stackoverflow.com/questions/11918123/how-to-convert-biginteger-value-to-hex-in-java
Hash Function - https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
                https://www.geeksforgeeks.org/sha-256-hash-in-java/
                https://www.baeldung.com/sha-256-hashing-java
                https://www.youtube.com/watch?v=dh8ura4rVUM
                https://stackoverflow.com/questions/48439278/aes-encryption-in-java-for-given-key
                https://www.baeldung.com/java-secure-aes-key
Encrypt - https://www.baeldung.com/java-aes-encryption-decryption
          https://www.youtube.com/watch?v=rnubKjspSdQ&t=303s
Write to a file - https://www.baeldung.com/java-write-to-file
Convert Byte arrays to hexadecimal - https://www.baeldung.com/java-byte-arrays-hex-strings
Padding - https://stackoverflow.com/questions/14478968/get-total-size-of-file-in-bytes
Convert bytes to hexadecimal - https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
Convert BigInteger to Byte Array - https://stackoverflow.com/questions/4407779/biginteger-to-byte
*/