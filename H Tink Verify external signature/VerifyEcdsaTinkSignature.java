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
* Funktion: überprüft eine extern erzeugte ecdsa-signatur mittels google tink
* Function: verifies an external generated ecdsa-signature with google tink
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
* 
* Das Programm benötigt die nachfolgenden Bibliotheken (siehe Github Archiv):
* The programm uses these external libraries (see Github Archive):
* jar-Datei/-File: tink-1.2.2.jar
* https://mvnrepository.com/artifact/com.google.crypto.tink/tink/1.2.2
* jar-Datei/-File: protobuf-java-3.10.0.jar
* https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java/3.10.0
* jar-Datei/-File: json-20190722.jar
* https://mvnrepository.com/artifact/org.json/json/20190722
*  
*/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;

public class VerifyEcdsaTinkSignature {

	static String pubKeyString = "";
	static String messageString = "";
	static String signatureString = "";
	public static byte[] xRec = null; // x-value of recoded public key
	public static byte[] yRec = null; // y-value of recoded public key

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		System.out.println("Verify a Classic ECDSA-signed message in Google Tink");
		TinkConfig.register();

		String publicKeyJsonFilenameTemplate = "ecdsa_tink_publickey_";
		String publicKeyJsonFilename = "";
		String filenameTemplate = "ecdsa_classic_data_";
		String filename;
		byte[] message = null;
		PublicKey pubKey;
		byte[] pubKeyByte = null;
		byte[] signatureClassic = null; // the signature from classic ecdsa
		boolean signatureVerification = false;
		int[] keylength = new int[] { 256, 384, 521 };
		// iterate through keylength
		for (int myKeylength : keylength) {
			filename = filenameTemplate + String.valueOf(myKeylength) + ".txt";
			publicKeyJsonFilename = publicKeyJsonFilenameTemplate + String.valueOf(myKeylength) + ".txt";
			pubKeyString = "";
			messageString = "";
			signatureString = "";
			// load data
			switch (myKeylength) {
			case 256: {
				loadData(filename);
				break;
			}
			case 384: {
				loadData(filename);
				break;
			}
			case 521: {
				loadData(filename);
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
			signatureClassic = Base64.getDecoder().decode(signatureString);
			// rebuild publicKey
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyByte);
			pubKey = keyFactory.generatePublic(publicKeySpec);
			// get x + y value of public key
			returnPublicKeyXY(pubKey); // writes to variables xRec and yRec
			// construct a tink-style public key value for json-file
			byte[] keyValueClassic = generateKeyValue(myKeylength);
			String keyValueClassicString = Base64.getEncoder().encodeToString(keyValueClassic); // saved in value-field
																								// of json-file
			// save tink public key in json-format, gets the generated primaryKeyId
			int keyId = SaveJson.writeJson(publicKeyJsonFilename, keyValueClassicString);
			// construct a tink-style signature
			byte[] signatureTink = generateSignature(keyId, signatureClassic);
			// reload the self created public key
			KeysetHandle keysetHandle = CleartextKeysetHandle
					.read(JsonKeysetReader.withFile(new File(publicKeyJsonFilename)));
			// verify signature
			signatureVerification = verifyMessage(keysetHandle, signatureTink, message);
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

	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	// source:
	// https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/EllipticCurves.java
	/**
	 * Transforms a big integer to its minimal signed form, i.e., no extra zero byte
	 * at the beginning except single one when the highest bit is set.
	 */
	private static byte[] toMinimalSignedNumber(byte[] bs) {
		// Remove zero prefixes.
		int start = 0;
		while (start < bs.length && bs[start] == 0) {
			start++;
		}
		if (start == bs.length) {
			start = bs.length - 1;
		}

		int extraZero = 0;
		// If the 1st bit is not zero, add 1 zero byte.
		if ((bs[start] & 0x80) == 0x80) {
			// Add extra zero.
			extraZero = 1;
		}
		byte[] res = new byte[bs.length - start + extraZero];
		System.arraycopy(bs, start, res, extraZero, bs.length - start);
		return res;
	}

	public static void returnPublicKeyXY(PublicKey pub) {
		ECPublicKey key = (ECPublicKey) pub;
		ECPoint ecp = key.getW();
		BigInteger x = ecp.getAffineX();
		BigInteger y = ecp.getAffineY();
		// convert big integer to byte[]
		byte[] x_array = x.toByteArray();
		if (x_array[0] == 0) {
			byte[] tmp = new byte[x_array.length - 1];
			System.arraycopy(x_array, 1, tmp, 0, tmp.length);
			x_array = tmp;
		}
		byte[] y_array = y.toByteArray();
		if (y_array[0] == 0) {
			byte[] tmp = new byte[y_array.length - 1];
			System.arraycopy(y_array, 1, tmp, 0, tmp.length);
			y_array = tmp;
		}
		// some byte[] need an additional x00 in the beginning
		xRec = toMinimalSignedNumber(x_array);
		yRec = toMinimalSignedNumber(y_array);
	}

	public static byte[] generateKeyValue(int keylength) {
		// header depends on keylength
		byte[] header = null;
		switch (keylength) {
		case 256: {
			header = fromHexString("12060803100218021A"); // only for ECDSA_P256
			break;
		}
		case 384: {
			header = fromHexString("12060804100318021A"); // only for ECDSA_P384
			break;
		}
		case 521: {
			header = fromHexString("12060804100418021A"); // only for ECDSA_P521
			break;
		}
		}
		int x_length = xRec.length;
		int y_length = yRec.length;
        // build the value-field with public key in x-/y-notation
		byte[] x_header = new byte[] { (byte) x_length };
		byte[] y_preheader = fromHexString("22");
		byte[] y_header = new byte[] { (byte) y_length };
		// join arrays
		byte[] kv = new byte[header.length + x_header.length + xRec.length + +y_preheader.length + y_header.length
				+ yRec.length];
		System.arraycopy(header, 0, kv, 0, header.length);
		System.arraycopy(x_header, 0, kv, header.length, x_header.length);
		System.arraycopy(xRec, 0, kv, (header.length + x_header.length), xRec.length);
		System.arraycopy(y_preheader, 0, kv, (header.length + x_header.length + xRec.length), y_preheader.length);
		System.arraycopy(y_header, 0, kv, (header.length + x_header.length + xRec.length + y_preheader.length),
				y_header.length);
		System.arraycopy(yRec, 0, kv,
				(header.length + x_header.length + xRec.length + y_preheader.length + y_header.length), yRec.length);
		return kv;
	}

	// this routine converts a Hex Dump String to a byte array
	private static byte[] fromHexString(final String encoded) {
		if ((encoded.length() % 2) != 0)
			throw new IllegalArgumentException("Input string must contain an even number of characters");
		final byte result[] = new byte[encoded.length() / 2];
		final char enc[] = encoded.toCharArray();
		for (int i = 0; i < enc.length; i += 2) {
			StringBuilder curr = new StringBuilder(2);
			curr.append(enc[i]).append(enc[i + 1]);
			result[i / 2] = (byte) Integer.parseInt(curr.toString(), 16);
		}
		return result;
	}

	public static byte[] generateSignature(int keyId, byte[] signatureByte) {
		byte[] header = fromHexString("01");
		// convert keyId from int to 4-byte byte[]
		byte[] keyIdBytes = ByteBuffer.allocate(4).putInt(keyId).array();
		// build the signature in tink-style with keyId included
		byte[] si = new byte[header.length + keyIdBytes.length + signatureByte.length];
		System.arraycopy(header, 0, si, 0, header.length);
		System.arraycopy(keyIdBytes, 0, si, header.length, keyIdBytes.length);
		System.arraycopy(signatureByte, 0, si, (header.length + keyIdBytes.length), signatureByte.length);
		return si;
	}

	public static boolean verifyMessage(KeysetHandle publicKeysetHandle, byte[] signature, byte[] message)
			throws UnsupportedEncodingException, GeneralSecurityException {
		Boolean verifiedBool = false;
		PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle);
		try {
			verifier.verify(signature, message);
			verifiedBool = true;
		} catch (GeneralSecurityException e) {
			verifiedBool = false;
		}
		return verifiedBool;
	}
}
