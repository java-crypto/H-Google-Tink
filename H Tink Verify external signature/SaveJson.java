package tinkExternalSignatureVerification;

/*
 * Diese Klasse gehört zu VerifyEcdsaTinkSignature.java
 * This class belongs to VerifyEcdsaTinkSignature.java
 * Herkunft/Origin: http://javacrypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 */

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;

public class SaveJson {

	public static int writeJson(String filename, String value) throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
		int keyId = newKeyId();
		String str = "{";
		writer.write(str + "\n");
		str = "    \"primaryKeyId\": " + keyId + ",";
		writer.append(str + "\n");
		str = "    \"key\": [{";
		writer.append(str + "\n");
		str = "        \"keyData\": {";
		writer.append(str + "\n");
		str = "            \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\",";
		writer.append(str + "\n");
		str = "            \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\",";
		writer.append(str + "\n");
		str = "            \"value\": \"" + value + "\"";
		writer.append(str + "\n");
		str = "        },";
		writer.append(str + "\n");
		str = "        \"outputPrefixType\": \"TINK\",";
		writer.append(str + "\n");
		str = "        \"keyId\": " + keyId + ",";
		writer.append(str + "\n");
		str = "        \"status\": \"ENABLED\"";
		writer.append(str + "\n");
		str = "    }]";
		writer.append(str + "\n");
		str = "}";
		writer.append(str);
		writer.close();

		return keyId;
	}

	// routines for keyId
	private static int newKeyId() {
		int keyId = randPositiveInt();
		keyId = randPositiveInt();
		return keyId;
	}

	// source:
	// https://github.com/google/tink/blob/08405fb55ba695b60b41f7f9ae198e5748152604/java/src/main/java/com/google/crypto/tink/KeysetManager.java
	/** @return positive random int */
	private static int randPositiveInt() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] rand = new byte[4];
		int result = 0;
		while (result == 0) {
			secureRandom.nextBytes(rand);
			result = ((rand[0] & 0x7f) << 24) | ((rand[1] & 0xff) << 16) | ((rand[2] & 0xff) << 8) | (rand[3] & 0xff);
		}
		return result;
	}
}
