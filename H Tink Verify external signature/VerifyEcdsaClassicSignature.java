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
* Funktion: überprüft eine ecdsa-signatur mittels jce
* Function: verifies an ecdsa-signature with jce
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*  
*/

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class VerifyEcdsaClassicSignature {

	static String pubKeyString = "";
	static String messageString = "";
	static String signatureString = "";

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
			InvalidKeyException, SignatureException {
		System.out.println("Verify a ECDSA-signed message");
		String filenameTemplate = "ecdsa_classic_data_";
		String filename;
		byte[] message = null;
		PublicKey pubKey;
		byte[] pubKeyByte = null;
		byte[] signature = null;
		String ecdsaHashtype = "";
		boolean signatureVerification = false;
		int[] keylength = new int[] { 256, 384, 521 };
		// iterate through keylength
		for (int myKeylength : keylength) {
			filename = filenameTemplate + String.valueOf(myKeylength) + ".txt";
			pubKeyString = "";
			messageString = "";
			signatureString = "";
			// load data
			switch (myKeylength) {
			case 256: {
				loadData(filename);
				ecdsaHashtype = "SHA256withECDSA";
				break;
			}
			case 384: {
				loadData(filename);
				ecdsaHashtype = "SHA512withECDSA";
				break;
			}
			case 521: {
				loadData(filename);
				ecdsaHashtype = "SHA512withECDSA";
				break;
			}
			default: {
				System.out.println("Error - signature keylength not supported");
				System.exit(0);
			}

			}
			// convert data from base64 to byte[]
			pubKeyByte = Base64.getDecoder().decode(pubKeyString);
			message = Base64.getDecoder().decode(messageString);
			signature = Base64.getDecoder().decode(signatureString);
			// rebuild publicKey
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyByte);
			pubKey = keyFactory.generatePublic(publicKeySpec);
			// verify signature
			signatureVerification = verifySignature(pubKey, ecdsaHashtype, message, signature);
			System.out.println("Data loaded from:" + filename + " The message is:" + new String(message, "UTF-8"));
			System.out.println("The provided signature is correct ?:" + signatureVerification);
		}
	}

	public static void loadData(String filenameLoad) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(filenameLoad));
		pubKeyString = reader.readLine();
		messageString = reader.readLine();
		signatureString = reader.readLine();
		reader.close();
	}

	public static Boolean verifySignature(PublicKey publicKey, String ecdsaHashtype, byte[] messageByte,
			byte[] signatureByte) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature publicSignature = Signature.getInstance(ecdsaHashtype);
		publicSignature.initVerify(publicKey);
		publicSignature.update(messageByte);
		return publicSignature.verify(signatureByte);
	}

}
