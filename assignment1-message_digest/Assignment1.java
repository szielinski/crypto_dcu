package assignment1;

import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

public class Assignment1 {
    public static void main(String[] args) {
        BigInteger primeP = new BigInteger(StaticVars.PRIME_P, StaticVars.BASE);
        BigInteger generatorG = new BigInteger(StaticVars.GENERATOR_G, StaticVars.BASE);
        BigInteger publicKeyA = new BigInteger(StaticVars.PUBLIC_KEY_A, StaticVars.BASE);
        
        SecureRandom randomGen = new SecureRandom();
        BigInteger privateB = BigInteger.probablePrime(StaticVars.PRIVATE_B_LENGTH, randomGen);
        
        BigInteger publicB = modularPower(generatorG, privateB, primeP);        
        BigInteger sharedS = modularPower(publicKeyA, privateB, primeP);
               
        BigInteger ab = new BigInteger(encrypt(StaticVars.MESSAGE, sharedS));
    }
    
    // calculate (base^exponent) % modulus
    public static BigInteger modularPower(BigInteger base, BigInteger exponent, BigInteger modulus){
        BigInteger r = new BigInteger("1");
        for(int i = exponent.bitLength(); i>=0; i--){
            if(exponent.testBit(i))
                r = ((r.multiply(r)).multiply(base)).mod(modulus);
            else
                r = (r.multiply(r)).mod(modulus);
        }
        return r;
    }
    
    //function to encrypt the message with the key. That's AES encryption in ECB using a SHA-256 digest. 
    public static byte[] encrypt(byte[] message, BigInteger key){
        
        //set up the SHA256 message digest
	MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
        }
        
        //apply the message digest
        byte[] keyDigest = sha256.digest(key.toByteArray());

        //set up the cipher settings
        SecretKeySpec cipherSettings = new SecretKeySpec(keyDigest, "AES");
        
        //initialise the AES cipher in ECB encrypt mode with no padding
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");            
	} catch (NoSuchPaddingException e) {
            System.out.println("NoSuchPaddingException");            
	}
        try {
            cipher.init(Cipher.ENCRYPT_MODE, cipherSettings);
	} catch (InvalidKeyException e) {
            System.out.println("InvalidKeyException");      
	}
        
        //encrypt the message
        byte[] result = null;
        try {
            result = cipher.doFinal(message);
        } catch (IllegalBlockSizeException e) {
            System.out.println("IllegalBlockSizeException");    
        } catch (BadPaddingException e) {	         
            System.out.println("BadPaddingException");      
        }
        
        return result;
    }
}
