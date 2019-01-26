package net.bplaced.javacrypto.tink;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 26.01.2019
* Funktion: verschlüsselt grosse Dateien und AAD-Daten mit Google Tink Streaming AES GCM
* Function: encrypts a large file and aad-data using Google Tink Streaming AES GCM
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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadFactory;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;

public final class H04_SymmetricStreamEncryptionTinkSaveKeysLargeFile {

	public static void main(String[] args) throws Exception {
		System.out.println(
				"H04 Symmetrische Stream-Verschlüsselung via Tink, Schlüssel Speicherung, mit AAD-Daten für große Dateien");

		TinkConfig.register();

		String aadtextString = "Hier stehen die AAD-Daten (additional authenticated data)";
		String filenameKeyString = "h03_streamingaesgcm256.txt";
		String filenamePlainString = "a11_test_1mb.dat";
		String filenameEncString = "h03_test_enc.txt";
		String filenameDecString = "h03_test_dec.txt";

		byte[] aadtextByte = new byte[0]; // damit das array auf jeden fall gefüllt ist
		aadtextByte = aadtextString.getBytes("utf-8");

		// schlüssel erzeugen
		System.out.println("\nSchlüsselerzeugung und Speicherung");
		// streaming gcm
		KeysetHandle keysetHandle = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);
		// StreamingAeasKeyTemplates. AES128_GCM_HKDF_4KB, AES256_GCM_HKDF_4KB
		// AES128_CTR_HMAC_SHA256_4KB, AES256_CTR_HMAC_SHA256_4KB

		// schlüssel speichern
		saveKeyJsonFormat(keysetHandle, filenameKeyString);
		System.out.println("Der erzeugte Schlüssel wurde gespeichert:" + filenameKeyString);
		System.out.println("Der Schlüssel ist im Format:" + keysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl());

		// falls ein schlüssel bereits vorhanden ist wird er so geladen:
		// KeysetHandle keysetHandle = loadKeyJsonFormat(filenameKeyString);

		// ist die datei filenamePlainString existent ?
		if (FileExistsCheck(filenamePlainString) == false) {
			System.out.println("Die Datei " + filenamePlainString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		}
		;

		// verschlüsselung
		System.out.println("\n# # # Verschlüsselung einer Datei # # #");
		System.out.println("Diese aadtext-Daten sind angefügt:\n" + new String(aadtextByte));
		encryptStreamingGcmAadTink(keysetHandle, filenamePlainString, filenameEncString, aadtextByte);
		System.out.println("Die Datei " + filenamePlainString + " wurde verschlüsselt in " + filenameEncString);
		Arrays.fill(aadtextByte, (byte) 0); // array löschen

		// entschlüsselung, einlesen des schlüssels und der verschlüsselten datei
		System.out.println("\n# # # Entschlüsselung einer Datei # # #");
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
		// lesen der schlüsseldatei
		KeysetHandle keysetHandleRead = loadKeyJsonFormat(filenameKeyString);
		System.out.println("Der Schlüssel wurde gelesen:" + filenameKeyString);
		// entschlüsseln der datei filenameEncString
		byte[] aadtextReadByte = decryptStreamingGcmAadTink(keysetHandleRead, filenameEncString, filenameDecString);
		System.out.println("Die Datei " + filenameEncString + " wurde entschlüsselt in " + filenameDecString);
		System.out.println("Diese aadtext-Daten sind angefügt:\n" + new String(aadtextReadByte));
	}

	public static void saveKeyJsonFormat(KeysetHandle keysetHandle, String filenameString) throws IOException {
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(filenameString)));
	}

	public static KeysetHandle loadKeyJsonFormat(String filenameString) throws GeneralSecurityException, IOException {
		return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(filenameString)));
	}

	public static void encryptStreamingGcmAadTink(KeysetHandle keysetHandle, String filenamePlainString,
			String filenameEncString, byte[] aadtextByte) throws Exception {
		// test auf ein nicht gefülltes aadtextByte array
		if (aadtextByte == null) {
			System.err.println("No data in aadtextByte, programm halted");
			System.exit(0);
		}
		try (FileInputStream fis = new FileInputStream(filenamePlainString);
				BufferedInputStream bis = new BufferedInputStream(fis);
				FileOutputStream out = new FileOutputStream(filenameEncString);
				BufferedOutputStream bos = new BufferedOutputStream(out)) {
			StreamingAead aead = StreamingAeadFactory.getPrimitive(keysetHandle);
			OutputStream os = aead.newEncryptingStream(bos, aadtextByte);
			// aad-data writer
			out.write(integerToFourBytes(aadtextByte.length));
			out.write(aadtextByte);
			// encryption
			byte[] buf = new byte[4096];
			int numRead = 0;
			while ((numRead = bis.read(buf)) >= 0) {
				os.write(buf, 0, numRead);
			}
			bis.close();
			os.close();
			Arrays.fill(buf, (byte) 0); // array löschen
		}
		Arrays.fill(aadtextByte, (byte) 0); // array löschen
	}

	public static byte[] decryptStreamingGcmAadTink(KeysetHandle keysetHandle, String filenameEncString,
			String filenameDecString) throws IOException, GeneralSecurityException {
		byte[] aadtextByte = null;
		try (FileInputStream fis = new FileInputStream(filenameEncString);
				BufferedInputStream bis = new BufferedInputStream(fis);
				FileOutputStream out = new FileOutputStream(filenameDecString);
				BufferedOutputStream bos = new BufferedOutputStream(out);) {
			// aad-data reader
			byte[] aadtextLengthByte = new byte[4];
			@SuppressWarnings("unused")
			int counter = fis.read(aadtextLengthByte, 0, 4);
			int aadtextLengthInt = byteArrayToInt(aadtextLengthByte);
			aadtextByte = new byte[aadtextLengthInt];
			counter = fis.read(aadtextByte, 0, aadtextLengthInt);
			// decryption
			StreamingAead aead = StreamingAeadFactory.getPrimitive(keysetHandle);
			InputStream in = aead.newDecryptingStream(bis, aadtextByte);
			byte[] ibuf = new byte[4096];
			int numRead = 0;
			while ((numRead = in.read(ibuf)) >= 0) {
				if (ibuf != null)
					bos.write(ibuf, 0, numRead);
			}
			Arrays.fill(ibuf, (byte) 0); // array löschen
		}
		return aadtextByte;
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
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

	public static int byteArrayToInt(byte[] b) {
		if (b.length == 4)
			return b[0] << 24 | (b[1] & 0xff) << 16 | (b[2] & 0xff) << 8 | (b[3] & 0xff);
		else if (b.length == 2)
			return 0x00 << 24 | 0x00 << 16 | (b[0] & 0xff) << 8 | (b[1] & 0xff);

		return 0;
	}

	public static final byte[] integerToFourBytes(int value) throws Exception {
		byte[] result = new byte[4];
		if ((value > Math.pow(2, 63)) || (value < 0)) {
			throw new Exception("Integer value " + value + " is larger than 2^63");
		}
		result[0] = (byte) ((value >>> 24) & 0xFF);
		result[1] = (byte) ((value >>> 16) & 0xFF);
		result[2] = (byte) ((value >>> 8) & 0xFF);
		result[3] = (byte) (value & 0xFF);
		return result;
	}
}