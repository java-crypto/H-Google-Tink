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
* Funktion: signiert eine Datei mit Google Tink ED25519
* Function: signs a file using Google Tink ED25519
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
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

public final class H08_SignatureTinkFile {

	public static void main(String[] args) throws Exception {
		System.out.println("H08 Signatur via Tink, Schlüssel Speicherung für eine Datei");
		System.out.println("\nHinweis: Bitte benutzen Sie dieses Programm nur bei kleineren Dateien bis"
				+ "\nzu einer Größe von 1 Megabyte, da die gesamte Datei in den Speicher geladen "
				+ "\nund dort signiert bzw. verifiziert wird.");
		
		TinkConfig.register();

		String filenamePrivateKeyString = "h08_private_ed25519.txt";
		String filenamePublicKeyString = "h08_public_ed25519.txt";
		String filenamePlainString = "a11_test_1mb.dat";
		String filenameSignatureString = "h08_signature.txt";

		// schlüssel erzeugen
		System.out.println("\nSchlüsselerzeugung und Speicherung");
		KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ED25519);
		// SignatureKeyTemplates. ECDSA_P256, ECDSA_P384, ECDSA_P521,
		// ECDSA_P256_IEEE_P1363, ECDSA_P384_IEEE_P1363, ECDSA_P521_IEEE_P1363, ED25519

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

		// signatur
		System.out.println("\n# # # Signatur einer Datei # # #");
		byte[] signatureByte = generateSignatureTink(privateKeysetHandle, filenamePlainString);
		System.out.println("Die Datei " + filenamePlainString + " hat diese Signatur:" + printHexBinary(signatureByte));
		// signatur speichern
		writeBytesToFileNio(signatureByte, filenameSignatureString);
		// signatur als base64-string
		System.out.println(
				"Die Datei hat diese Signatur als Base64String:" + Base64.getEncoder().encodeToString(signatureByte));

		// verifizierung, einlesen des schlüssels und der signatur datei
		System.out.println("\n# # # Signatur Verifizierung einer Datei # # #");
		if (FileExistsCheck(filenamePublicKeyString) == false) {
			System.out.println("Die Datei " + filenamePublicKeyString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		if (FileExistsCheck(filenameSignatureString) == false) {
			System.out.println("Die Datei " + filenameSignatureString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;
		// lesen der schlüsseldatei
		KeysetHandle publicKeysetHandleRead = loadKeyJsonFormat(filenamePublicKeyString);
		System.out.println("Der Schlüssel wurde gelesen:" + filenamePublicKeyString);
		// verifizierung der datei filenamePlainString
		Boolean verifiedBool = verifySignatureTink(publicKeysetHandleRead, filenamePlainString,
				filenameSignatureString);
		System.out.println("Die Signatur für die Datei " + filenamePlainString + " ist korrekt:" + verifiedBool);
	}

	public static void saveKeyJsonFormat(KeysetHandle keysetHandle, String filenameString) throws IOException {
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(filenameString)));
	}

	public static KeysetHandle loadKeyJsonFormat(String filenameString) throws GeneralSecurityException, IOException {
		return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(filenameString)));
	}

	public static byte[] generateSignatureTink(KeysetHandle privateKeysetHandle, String filenamePlainString)
			throws GeneralSecurityException {
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// signatur
		PublicKeySign signer = PublicKeySignFactory.getPrimitive(privateKeysetHandle);
		return signer.sign(plaintextByte);
	}

	public static Boolean verifySignatureTink(KeysetHandle publicKeysetHandle, String filenamePlainString,
			String filenameSignatureString) throws GeneralSecurityException {
		// einlesen des plaintextes
		byte[] plaintextByte = readBytesFromFileNio(filenamePlainString);
		// einlesen des hmac
		byte[] signatureByte = readBytesFromFileNio(filenameSignatureString);
		Boolean verifiedBool = false;
		PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle);
		try {
			verifier.verify(signatureByte, plaintextByte);
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