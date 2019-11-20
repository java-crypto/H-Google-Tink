package tinkPbe;

/*
*  
* Diese Klasse gehört zu diesen beiden Hauptklassen
* This class belongs to these main classes:
* TinkPbeConsole.java | TinkPbeGui.java 
* 
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 20.11.2019
* Funktion: verschlüsselt und entschlüsselt einen Text mittels Google Tink
*           im Modus AES GCM 256 Bit. Der Schlüssel wird mittels PBE
*           (Password based encryption) erzeugt.
* Function: encrypts and decrypts a text message with Google Tink.
*           Used Mode is AES GCM 256 Bit. The key is generated with PBE
*           (Password based encryption).
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadFactory;

public class TinkPbe {

	public static String encrypt(char[] passwordChar, String plaintextString)
			throws GeneralSecurityException, IOException {
		byte[] keyByte = pbkdf2(passwordChar);
		String valueString = buildValue(keyByte);
		String jsonKeyString = writeJson(valueString);
		KeysetHandle keysetHandleOwn = CleartextKeysetHandle.read(JsonKeysetReader.withString(jsonKeyString));
		// initialisierung
		Aead aead = AeadFactory.getPrimitive(keysetHandleOwn);
		// verschlüsselung
		byte[] ciphertextByte = aead.encrypt(plaintextString.getBytes("utf-8"), null); // no aad-data
		return Base64.getEncoder().encodeToString(ciphertextByte);
	}

	public static String decrypt(char[] passwordChar, String ciphertextString)
			throws GeneralSecurityException, IOException {
		byte[] keyByte = pbkdf2(passwordChar);
		String valueString = buildValue(keyByte);
		String jsonKeyString = writeJson(valueString);
		KeysetHandle keysetHandleOwn = CleartextKeysetHandle.read(JsonKeysetReader.withString(jsonKeyString));
		// initialisierung
		Aead aead = AeadFactory.getPrimitive(keysetHandleOwn);
		// verschlüsselung
		byte[] plaintextByte = aead.decrypt(Base64.getDecoder().decode(ciphertextString), null); // no aad-data
		return new String(plaintextByte, StandardCharsets.UTF_8);
	}

	private static byte[] pbkdf2(char[] passwordChar)
			throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
		final byte[] passwordSaltByte = "11223344556677881122334455667788".getBytes("UTF-8");
		final int PBKDF2_ITERATIONS = 10000; // anzahl der iterationen, höher = besser = langsamer
		final int SALT_SIZE_BYTE = 256; // grösse des salts, sollte so groß wie der hash sein
		final int HASH_SIZE_BYTE = 256; // größe das hashes bzw. gehashten passwortes, 128 byte = 512 bit
		byte[] passwordHashByte = new byte[HASH_SIZE_BYTE]; // das array nimmt das gehashte passwort auf
		PBEKeySpec spec = new PBEKeySpec(passwordChar, passwordSaltByte, PBKDF2_ITERATIONS, HASH_SIZE_BYTE);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		passwordHashByte = skf.generateSecret(spec).getEncoded();
		return passwordHashByte;
	}

	private static String buildValue(byte[] gcmKeyByte) {
		// test for correct key length
		if ((gcmKeyByte.length != 16) && (gcmKeyByte.length != 32)) {
			throw new NumberFormatException("key is not 16 or 32 bytes long");
		}
		// header byte depends on keylength
		byte[] headerByte = new byte[2]; // {26, 16 }; // 1A 10 for 128 bit, 1A 20 for 256 Bit
		if (gcmKeyByte.length == 16) {
			headerByte = new byte[] { 26, 16 };
		} else {
			headerByte = new byte[] { 26, 32 };
		}
		byte[] keyByte = new byte[headerByte.length + gcmKeyByte.length];
		System.arraycopy(headerByte, 0, keyByte, 0, headerByte.length);
		System.arraycopy(gcmKeyByte, 0, keyByte, headerByte.length, gcmKeyByte.length);
		String keyBase64 = Base64.getEncoder().encodeToString(keyByte);
		return keyBase64;
	}

	private static String writeJson(String value) {
		int keyId = 1234567; // fix
		String str = "{\n";
		str = str + "    \"primaryKeyId\": " + keyId + ",\n";
		str = str + "    \"key\": [{\n";
		str = str + "        \"keyData\": {\n";
		str = str + "            \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\",\n";
		str = str + "            \"keyMaterialType\": \"SYMMETRIC\",\n";
		str = str + "            \"value\": \"" + value + "\"\n";
		str = str + "        },\n";
		str = str + "        \"outputPrefixType\": \"TINK\",\n";
		str = str + "        \"keyId\": " + keyId + ",\n";
		str = str + "        \"status\": \"ENABLED\"\n";
		str = str + "    }]\n";
		str = str + "}";
		return str;
	}
}
