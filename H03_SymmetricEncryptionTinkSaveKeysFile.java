package net.bplaced.javacrypto.tink;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 23.01.2019
* Funktion: verschl�sselt eine Datei und AAD-Daten mit Google Tink AES GCM
* Function: encrypts a file and aad-data using Google Tink AES GCM
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Pr�fen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
* 
* Das Programm ben�tigt die nachfolgende Bibliotheken:
* The programm uses these external libraries:
* jar-Datei: https://mvnrepository.com/artifact/com.google.crypto.tink/tink 
* jar-Datei: https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java
* jar-Datei: https://mvnrepository.com/artifact/org.json/json
*/

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
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;

public final class H03_SymmetricEncryptionTinkSaveKeysFile {

	public static void main(String[] args) throws Exception {
		System.out.println(
				"H03 Symmetrische Verschl�sselung via Tink, Schl�ssel Speicherung, mit AAD-Daten und mit einer Datei");
		System.out.println("\nHinweis: Bitte benutzen Sie dieses Programm nur bei kleineren Dateien bis"
				+ "\nzu einer Gr��e von 1 Megabyte, da die gesamte Datei in den Speicher geladen "
				+ "\nund dort ver- bzw. entschl�sselt wird.");

		AeadConfig.register();

		String aadtextString = "Hier stehen die AAD-Daten (additional authenticated data)";
		String filenameKeyString = "h03_aesgcm256.txt";
		String filenamePlainString = "a11_test_1mb.dat";
		String filenameEncString = "h03_test_enc.txt";
		String filenameDecString = "h03_test_dec.txt";

		byte[] aadtextByte = new byte[0]; // damit das array auf jeden fall gef�llt ist
		aadtextByte = aadtextString.getBytes("utf-8");
		
		// schl�ssel erzeugen
		System.out.println("\nSchl�sselerzeugung und Speicherung");
		KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
		// AeadKeyTemplates. AES128_GCM, AES256_GCM, AES128_EAX, AES256_EAX, AES128_CTR_HMAC_SHA256,
		// CHACHA20_POLY1305

		// schl�ssel speichern
		saveKeyJsonFormat(keysetHandle, filenameKeyString);
		System.out.println("Der erzeugte Schl�ssel wurde gespeichert:" + filenameKeyString);
		System.out.println("Der Schl�ssel ist im Format:" + keysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl());

		// falls ein schl�ssel bereits vorhanden ist wird er so geladen:
		// KeysetHandle keysetHandle = loadKeyJsonFormat(filenameKeyString);

		// ist die datei filenamePlainString existent ?
		if (FileExistsCheck(filenamePlainString) == false) {
			System.out.println("Die Datei " + filenamePlainString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;

		// verschl�sselung
		System.out.println("\n# # # Verschl�sselung einer Datei # # #");
		encryptSymmetricWithAadTink(keysetHandle, filenamePlainString, filenameEncString, aadtextByte);
		System.out.println("Die Datei " + filenamePlainString + " wurde verschl�sselt in " + filenameEncString);
		System.out.println("Diese aadtext-Daten sind angef�gt:\n" + new String(aadtextByte));

		// entschl�sselung, einlesen des schl�ssels und der verschl�sselten datei
		System.out.println("\n# # # Entschl�sselung einer Datei # # #");
		if (FileExistsCheck(filenameKeyString) == false) {
			System.out.println("Die Datei " + filenameKeyString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		if (FileExistsCheck(filenameEncString) == false) {
			System.out.println("Die Datei " + filenameEncString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		// lesen der schl�sseldatei
		KeysetHandle keysetHandleRead = loadKeyJsonFormat(filenameKeyString);
		System.out.println("Der Schl�ssel wurde gelesen:" + filenameKeyString);
		// entschl�sseln der datei filenameEncString
		byte[] aadtextReadByte = decryptSymmetricWithAadTink(keysetHandleRead, filenameEncString, filenameDecString);
		System.out.println("Die Datei " + filenameEncString + " wurde entschl�sselt in " + filenameDecString);
		System.out.println("Diese aadtext-Daten sind angef�gt:\n" + new String(aadtextReadByte));
	}

	public static void saveKeyJsonFormat(KeysetHandle keysetHandle, String filenameString) throws IOException {
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(filenameString)));
	}

	public static KeysetHandle loadKeyJsonFormat(String filenameString) throws GeneralSecurityException, IOException {
		return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(filenameString)));
	}

	public static void encryptSymmetricWithAadTink(KeysetHandle keysetHandle, String filenamePlainString,
			String filenameEncString, byte[] aadtextByte)
			throws GeneralSecurityException, FileNotFoundException, IOException {
		// test auf ein nicht gef�lltes aadtextByte array
		if (aadtextByte == null) {
			System.err.println("No data in aadtextByte, programm halted");
			System.exit(0);
		}
		// initialisierung
		Aead aead = AeadFactory.getPrimitive(keysetHandle);
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// verschl�sselung
		byte[] ciphertextByte = aead.encrypt(plaintextByte, aadtextByte);
		Arrays.fill(plaintextByte, (byte) 0); // plaintextByte l�schen
		// aadtextByte und ciphertextByte speichern
		writeTwoByteArraysToFileNio(aadtextByte, ciphertextByte, filenameEncString);
		Arrays.fill(ciphertextByte, (byte) 0); // ciphertextByte l�schen
	}

	public static byte[] decryptSymmetricWithAadTink(KeysetHandle keysetHandle, String filenameEncString,
			String filenameDecString) throws GeneralSecurityException, FileNotFoundException, IOException {
		// initialisierung
		Aead aead = AeadFactory.getPrimitive(keysetHandle);
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
		// entschl�sselung
		byte[] decryptedtextByte = aead.decrypt(ciphertextByte, aadtextByte);
		Arrays.fill(ciphertextByte, (byte) 0); // ciphertextByte l�schen
		// decryptedtextByte speichern
		writeBytesToFileNio(decryptedtextByte, filenameDecString);
		// decryptedtextByte l�schen
		Arrays.fill(decryptedtextByte, (byte) 0);
		return aadtextByte;
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
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
}