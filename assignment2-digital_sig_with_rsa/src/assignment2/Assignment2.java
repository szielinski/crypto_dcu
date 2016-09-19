package assignment2;

import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.nio.file.Paths;
import java.util.Scanner;
import java.nio.file.*;

public class Assignment2 {
    public static void main(String[] args) {
        
        BigInteger primeP;
        BigInteger primeQ;
        BigInteger N;
        BigInteger phiN;
        BigInteger e = new BigInteger(StaticVars.EXP_E, StaticVars.RADIX_E);
        
        do{
            //generate two distinct 512-bit probable primes p and q
            SecureRandom randomGen = new SecureRandom();
            primeP = BigInteger.probablePrime(StaticVars.PRIMES_LENGTH, randomGen);
            primeQ = BigInteger.probablePrime(StaticVars.PRIMES_LENGTH, randomGen);

            // calculate N = pq
            N = primeP.multiply(primeQ);

            //calculate the Euler totient function phi(N)
            phiN = phi(primeP, primeQ);
            
        } while(!isRelPrime(phiN, e) || primeP.equals(primeQ)); //ensure that e is relatively prime to phi(N) and that p and q are two distinct primes
               
        //compute the value for the decryption exponent d, the multiplicative inverse of e (mod phi(N))
        BigInteger d = multInverse(e, phiN);   
        
        //read the code of this program stored in a separate file
        String code = "";
        try{        
            code = readTextFile(StaticVars.CODE_LOCATION);
        } catch(IOException io){
            System.out.println("Could not read the code from the text file");
        }
        
        //apply SHA-256 to get the digest of the code 
        BigInteger hashedCode = new BigInteger(hashString(code));
        
        //convert the digest to ciphertext using the private exponent "d"
        BigInteger cipherSignature = modularPower(hashedCode, d, N);
         
        //print the results required for this assignment
        System.out.println("The 1024-bit modulus N in hexadecimal is: " + N.toString(StaticVars.RADIX_HEX));  
        System.out.println("The digitally signed code digest is: " + cipherSignature.toString());
        System.out.println("The digitally signed code digest in hexadecimal is: " + cipherSignature.toString(StaticVars.RADIX_HEX));
        System.out.println("The code, as it is read in by the program is: " + code);
    }
    
    //returns the multiplicative inverse of e
    public static BigInteger multInverse(BigInteger e, BigInteger phiN){
        BigInteger x = BigInteger.ZERO;
        
        BigInteger lastX = BigInteger.ONE;
        
        while(!phiN.equals(BigInteger.ZERO)){
            BigInteger quotient = e.divide(phiN);
            
            BigInteger temp = phiN;
            phiN = e.mod(phiN);
            e = temp;
            
            temp = x;
            x = lastX.subtract((quotient).multiply(x));
            lastX = temp;
        }
        return lastX;
    }
    
    //checks whether two arguments are relatively prime
    public static boolean isRelPrime(BigInteger a, BigInteger b){
        return gcd(a, b).equals(BigInteger.ONE);
    }
    
    //returns the greatest common divisor using the division-based approach
    public static BigInteger gcd(BigInteger a, BigInteger b){
        while(!b.equals(BigInteger.ZERO)){
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }       
        return a;
    }
    
    //computes the euler totient function of two different primes
    public static BigInteger phi(BigInteger primeP, BigInteger primeQ){
        primeP = primeP.subtract(BigInteger.ONE);
        primeQ = primeQ.subtract(BigInteger.ONE);
        
        return primeP.multiply(primeQ);
    }
    
    //return a SHA-256 digest of a String message
    public static byte[] hashString(String message){
        MessageDigest sha256 = null;
        
        try{
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: NoSuchAlgorithmException occured during the execution of the hashString function!");
        }        
        sha256.update(message.getBytes());
        
        return sha256.digest();        
    }
       
    // THE DECRYPTION METHOD - calculate (base^exponent) % modulus
    public static BigInteger modularPower(BigInteger base, BigInteger exponent, BigInteger modulus){
        
        //special negative exponent case
        if(exponent.compareTo(BigInteger.ZERO) == -1){
            base = multInverse(base, modulus);
            exponent = exponent.abs();
        }
        
        BigInteger r = BigInteger.ONE;
        for(int i = exponent.bitLength(); i>=0; i--){
            if(exponent.testBit(i))
                r = ((r.multiply(r)).multiply(base)).mod(modulus);
            else
                r = (r.multiply(r)).mod(modulus);
        }
        return r;
    }
    
    //return contents of a text file as String - WARNING: IGNORES WHITESPACE!
    public static String readTextFile(String fileName) throws IOException{
        String contents = "";
        Path path = Paths.get(fileName);
        Scanner scanner = new Scanner(path);
        while(scanner.hasNext())
            contents += scanner.next();
        
        return contents;
    }
}
