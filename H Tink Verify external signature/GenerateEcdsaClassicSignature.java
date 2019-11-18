package tinkExternalSignatureVerification;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 18.11.2019
* Funktion: erzeugt eine ecdsa-signatur mittels jce
* Function: generates an ecdsa-signature with jce
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*  
*/

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

public class GenerateEcdsaClassicSignature {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException, IOException {
		System.out.println("Generate a ECDSA Private-/PublicKey and signs a message");

		byte[] message = "This is the message".getBytes("utf-8");
		String messageString = "";
		String filenameTemplate = "ecdsa_classic_data_";
		String filename;
		byte[] signature = null;
		String signatureString = "";
		PrivateKey privKey;
		PublicKey pubKey;
		String pubKeyString = "";
		int[] keylength = new int[] { 256, 384, 521 };
		// iterate through keylength
		for (int myKeylength : keylength) {
			filename = filenameTemplate + String.valueOf(myKeylength) + ".txt";
			// generate keypair
			KeyPair keyPair = generateEcdsaClassicKeyPair(myKeylength);
			privKey = keyPair.getPrivate();
			pubKey = keyPair.getPublic();
			signature = null;
			// sign the message
			switch (myKeylength) {
			case 256: {
				signature = signEcdsaClassic(privKey, message, "SHA256withECDSA");
				break;
			}
			case 384: {
				signature = signEcdsaClassic(privKey, message, "SHA512withECDSA");
				break;
			}
			case 521: {
				signature = signEcdsaClassic(privKey, message, "SHA512withECDSA");
				break;
			}
			default: {
				System.out.println("Error - signature keylength not supported");
				System.exit(0);
			}

			}
			// convert data to base64
			pubKeyString = Base64.getEncoder().encodeToString(pubKey.getEncoded());
			messageString = Base64.getEncoder().encodeToString(message);
			signatureString = Base64.getEncoder().encodeToString(signature);
			// save data to file
			writeData(filename, pubKeyString, messageString, signatureString);
			System.out.println("Data written to:" + filename);
		}

	}

	public static KeyPair generateEcdsaClassicKeyPair(int keylengthInt)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("EC");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keypairGenerator.initialize(keylengthInt, random);
		return keypairGenerator.generateKeyPair();
	}

	public static byte[] signEcdsaClassic(PrivateKey privateKey, byte[] message, String ecdsaHashtype)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature signature = Signature.getInstance(ecdsaHashtype);
		signature.initSign(privateKey);
		signature.update(message);
		byte[] sigByte = signature.sign();
		return sigByte;
	}

	public static void writeData(String filenameWrite, String pubKeyWrite, String messageWrite, String signatureWrite)
			throws IOException {
		FileWriter fw = new FileWriter(filenameWrite);
		fw.write(pubKeyWrite + "\n");
		fw.write(messageWrite + "\n");
		fw.write(signatureWrite + "\n");
		fw.write(
				"This file contains data in base64-format: publicKey, message, signature. Number in filename is keylength.");
		fw.flush();
		fw.close();
	}

}
