package net.bplaced.javacrypto.tink;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 28.01.2019
* Funktion: verschlüsselt eine Datei und AAD-Daten mit Google Tink Hybrid AES GCM
* Function: encrypts a file and aad-data using Google Tink Hybrid AES GCM
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
* 
* Das Programm benötigt die nachfolgende Bibliotheken:
* The programm uses these external libraries:
* jar-Datei: https://mvnrepository.com/artifact/com.google.crypto.tink/tink 
* jar-Datei: https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java
* jar-Datei: https://mvnrepository.com/artifact/org.json/json
*/

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;

public final class H06_HybridEncryptionTinkFile {

	public static void main(String[] args) throws Exception {
		System.out.println("H06 Hybride Verschlüsselung via Tink, Schlüssel Speicherung, mit AAD-Daten für eine Datei");
		System.out.println("\nHinweis: Bitte benutzen Sie dieses Programm nur bei kleineren Dateien bis"
				+ "\nzu einer Größe von 1 Megabyte, da die gesamte Datei in den Speicher geladen "
				+ "\nund dort der ver- bzw. entschlüsselt wird.");

		TinkConfig.register();

		String aadtextString = "Hier stehen die AAD-Daten (additional authenticated data)";
		String filenamePrivateKeyString = "h06_private_hybridgcm128.txt";
		String filenamePublicKeyString = "h06_public_hybridgcm128.txt";
		String filenamePlainString = "a11_test_1mb.dat";
		String filenameEncString = "h06_test_enc.txt";
		String filenameDecString = "h06_test_dec.txt";

		byte[] aadtextByte = new byte[0]; // damit das array auf jeden fall gefüllt ist
		aadtextByte = aadtextString.getBytes("utf-8");

		// schlüssel erzeugen
		System.out.println("\nSchlüsselerzeugung und Speicherung");
		KeysetHandle privateKeysetHandle = KeysetHandle
				.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
		// HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
		// HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
		
		// öffentlichen schlüssel erzeugen
		KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

		// schlüssel speichern
		// private key
		saveKeyJsonFormat(privateKeysetHandle, filenamePrivateKeyString);
		System.out.println("Der erzeugte private Schlüssel wurde gespeichert:" + filenamePrivateKeyString);
		System.out.println(
				"Der Schlüssel ist im Format:" + privateKeysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl());
		// public key
		saveKeyJsonFormat(publicKeysetHandle, filenamePublicKeyString);
		System.out.println("Der erzeugte öffentliche Schlüssel wurde gespeichert:" + filenamePublicKeyString);
		System.out.println(
				"Der Schlüssel ist im Format:" + publicKeysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		CleartextKeysetHandle.write(privateKeysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
		System.out.println("\nPubKey:\t" + new String(outputStream.toByteArray()));
		
		// falls ein schlüssel bereits vorhanden ist wird er so geladen:
		// KeysetHandle keysetHandle = loadKeyJsonFormat(filenameKeyString);

		// ist die datei filenamePlainString existent ?
		if (FileExistsCheck(filenamePlainString) == false) {
			System.out.println("Die Datei " + filenamePlainString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;

		// verschlüsselung
		System.out.println("\n# # # Hybride Verschlüsselung einer Datei # # #");
		encryptHybridWithAadTink(publicKeysetHandle, filenamePlainString, filenameEncString, aadtextByte);
		System.out.println("Die Datei " + filenamePlainString + " wurde verschlüsselt in " + filenameEncString);
		System.out.println("Diese aadtext-Daten sind angefügt:\n" + new String(aadtextByte));

		// entschlüsselung, einlesen des schlüssels und der verschlüsselten datei
		System.out.println("\n# # # Hybride Entschlüsselung einer Datei # # #");
		if (FileExistsCheck(filenamePrivateKeyString) == false) {
			System.out
					.println("Die Datei " + filenamePrivateKeyString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		if (FileExistsCheck(filenameEncString) == false) {
			System.out.println("Die Datei " + filenameEncString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		// lesen der schlüsseldatei
		KeysetHandle privateKeysetHandleRead = loadKeyJsonFormat(filenamePrivateKeyString);
		System.out.println("Der Schlüssel wurde gelesen:" + filenamePrivateKeyString);
		// entschlüsseln der datei filenameEncString
		byte[] aadtextReadByte = decryptHybridWithAadTink(privateKeysetHandleRead, filenameEncString,
				filenameDecString);
		System.out.println("Die Datei " + filenameEncString + " wurde entschlüsselt in " + filenameDecString);
		System.out.println("Diese aadtext-Daten sind angefügt:\n" + new String(aadtextReadByte));
	}

	public static void saveKeyJsonFormat(KeysetHandle keysetHandle, String filenameString) throws IOException {
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(filenameString)));
	}

	public static KeysetHandle loadKeyJsonFormat(String filenameString) throws GeneralSecurityException, IOException {
		return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(filenameString)));
	}

	public static void encryptHybridWithAadTink(KeysetHandle publicKeysetHandle, String filenamePlainString,
			String filenameEncString, byte[] aadtextByte)
			throws GeneralSecurityException, FileNotFoundException, IOException {
		// test auf ein nicht gefülltes aadtextByte array
		if (aadtextByte == null) {
			System.err.println("No data in aadtextByte, programm halted");
			System.exit(0);
		}
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// verschlüsselung
		HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(publicKeysetHandle);
		byte[] ciphertextByte = hybridEncrypt.encrypt(plaintextByte, aadtextByte);
		Arrays.fill(plaintextByte, (byte) 0); // plaintextByte löschen
		// aadtextByte und ciphertextByte speichern
		writeTwoByteArraysToFileNio(aadtextByte, ciphertextByte, filenameEncString);
		Arrays.fill(ciphertextByte, (byte) 0); // ciphertextByte löschen
	}

	public static byte[] decryptHybridWithAadTink(KeysetHandle privateKeysetHandle, String filenameEncString,
			String filenameDecString) throws GeneralSecurityException, FileNotFoundException, IOException {
		HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(privateKeysetHandle);
		// einlesen des aadtextByte und ciphertextByte
		byte[] aadtextByte = null;
		byte[] ciphertextByte = null;
		try (DataInputStream dataIn = new DataInputStream(new FileInputStream(filenameEncString))) {
			int aadtextSizeInt = dataIn.readInt();
			aadtextByte = new byte[aadtextSizeInt];
			dataIn.read(aadtextByte, 0, aadtextSizeInt);
			int ciphertextSizeInt = dataIn.readInt();
			ciphertextByte = new byte[ciphertextSizeInt];
			dataIn.read(ciphertextByte, 0, ciphertextSizeInt);
		}
		// entschlüsselung
		byte[] decryptedtextByte = hybridDecrypt.decrypt(ciphertextByte, aadtextByte);
		Arrays.fill(ciphertextByte, (byte) 0); // ciphertextByte löschen
		// decryptedtextByte speichern
		writeBytesToFileNio(decryptedtextByte, filenameDecString);
		// decryptedtextByte löschen
		Arrays.fill(decryptedtextByte, (byte) 0);
		return aadtextByte;
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}

	private static void writeBytesToFileNio(byte[] byteToFileByte, String filenameString) {
		try {
			Path path = Paths.get(filenameString);
			Files.write(path, byteToFileByte);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static byte[] readBytesFromFileNio(String filenameString) {
		byte[] byteFromFileByte = null;
		try {
			byteFromFileByte = Files.readAllBytes(Paths.get(filenameString));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteFromFileByte;
	}

	private static void writeTwoByteArraysToFileNio(byte[] firstByte, byte[] secondByte, String filenameString)
			throws FileNotFoundException, IOException {
		try (DataOutputStream out = new DataOutputStream(new FileOutputStream(filenameString))) {
			out.writeInt(firstByte.length);
			out.write(firstByte);
			out.writeInt(secondByte.length);
			out.write(secondByte);
		}
	}

	public static String toHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer(bytes.length * 2);
		for (int i = 0; i < bytes.length; i++) {
			sb.append(toHex(bytes[i] >> 4));
			sb.append(toHex(bytes[i]));
		}

		return sb.toString();
	}

	private static char toHex(int nibble) {
		final char[] hexDigit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		return hexDigit[nibble & 0xF];
	}

}