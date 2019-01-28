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
* Funktion: berechnet und verifiziert den HMAC einer Datei mit Google Tink HMAC
* Function: calculates and verifies the hmac of a file using Google Tink HMAC
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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Base64;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacFactory;
import com.google.crypto.tink.mac.MacKeyTemplates;

public final class H07_HmacTinkFile {

	public static void main(String[] args) throws Exception {
		System.out.println("H07 HMAC einer Datei via Tink");
		System.out.println("\nHinweis: Bitte benutzen Sie dieses Programm nur bei kleineren Dateien bis"
				+ "\nzu einer Größe von 1 Megabyte, da die gesamte Datei in den Speicher geladen "
				+ "\nund dort der HMAC berechnet wird.");
		
		AeadConfig.register();

		String filenameKeyString = "h07_hmac_gcm128.txt";
		String filenamePlainString = "a11_test_1mb.dat";
		String filenameHmacString = "h07_hmac.txt";

		// schlüssel erzeugen
		System.out.println("\nSchlüsselerzeugung und Speicherung");
		KeysetHandle keysetHandle = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
		// MacKeyTemplates.HMAC_SHA256_128BITTAG
		// MacKeyTemplates.HMAC_SHA256_256BITTAG

		// schlüssel speichern
		// hmac key
		saveKeyJsonFormat(keysetHandle, filenameKeyString);
		System.out.println("Der erzeugte Schlüssel wurde gespeichert:" + filenameKeyString);
		System.out.println("Der Schlüssel ist im Format:" + keysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl());
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
		System.out.println("\nHMAC-Key:\t" + new String(outputStream.toByteArray()));

		// falls ein schlüssel bereits vorhanden ist wird er so geladen:
		// KeysetHandle keysetHandle = loadKeyJsonFormat(filenameKeyString);

		// ist die datei filenamePlainString existent ?
		if (FileExistsCheck(filenamePlainString) == false) {
			System.out.println("Die Datei " + filenamePlainString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;

		// hmac erzeugen
		System.out.println("\n# # # HMAC einer Datei # # #");
		byte[] hmacByte = createHmacTink(keysetHandle, filenamePlainString);
		System.out.println("Die Datei " + filenamePlainString + " hat diesen HMAC:" + printHexBinary(hmacByte));

		// hmac speichern
		writeBytesToFileNio(hmacByte, filenameHmacString);
		// hmac als base64-string
		System.out.println("Die Datei hat diesen HMAC als Base64String:" + Base64.getEncoder().encodeToString(hmacByte));

		// verifizierung, einlesen des schlüssels und des hmac
		System.out.println("\n# # # HMAC Verifizierung einer Datei # # #");
		if (FileExistsCheck(filenameKeyString) == false) {
			System.out.println("Die Datei " + filenameKeyString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		if (FileExistsCheck(filenameHmacString) == false) {
			System.out.println("Die Datei " + filenameHmacString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		// lesen der schlüsseldatei
		KeysetHandle keysetHandleRead = loadKeyJsonFormat(filenameKeyString);
		System.out.println("Der Schlüssel wurde gelesen:" + filenameKeyString);
		// verifizierung der datei filenamePlainString
		Boolean verifiedBool = verifyHmacTink(keysetHandleRead, filenamePlainString, filenameHmacString);
		System.out.println("Der HMAC für die Datei " + filenamePlainString + " ist korrekt:" + verifiedBool);
	}

	public static void saveKeyJsonFormat(KeysetHandle keysetHandle, String filenameString) throws IOException {
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(filenameString)));
	}

	public static KeysetHandle loadKeyJsonFormat(String filenameString) throws GeneralSecurityException, IOException {
		return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(filenameString)));
	}

	public static byte[] createHmacTink(KeysetHandle keysetHandle, String filenamePlainString)
			throws GeneralSecurityException, FileNotFoundException, IOException {
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// hmac berechnung
		Mac hmac = MacFactory.getPrimitive(keysetHandle);
		return hmac.computeMac(plaintextByte);
	}

	public static Boolean verifyHmacTink(KeysetHandle keysetHandle, String filenamePlainString,
			String filenameHmacString) throws GeneralSecurityException {
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// einlesen des hmac
		byte[] hmacByte = readBytesFromFileNio(filenameHmacString);

		Mac hmac = MacFactory.getPrimitive(keysetHandle);
		Boolean verifiedBool = false;
		try {
			hmac.verifyMac(hmacByte, plaintextByte);
			verifiedBool = true;
		} catch (GeneralSecurityException e) {
			verifiedBool = false;
		}
		return verifiedBool;
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