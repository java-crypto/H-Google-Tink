package net.bplaced.javacrypto.tink;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 22.01.2019
* Funktion: verschlüsselt einen String mit Google Tink Routinen
* Function: encrypts a String using Google Tink Encryption
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
*/
import java.io.ByteArrayOutputStream;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;

public final class H02_AllSymmetricEncryptionsTinkString {

	public static void main(String[] args) throws Exception {
		System.out.println("H02 Alle Symmetrischen Verschlüsselungen Tink mit einem String");
		AeadConfig.register();

		String plaintextString = "Das ist der zu verschluesselnde String.";
		String aadtextString = "Hier stehen die AAD-Daten";

		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		byte[] aadtextByte = aadtextString.getBytes("utf-8");

		KeysetHandle keysetHandle = null;
		// wir probieren alle 6 möglichen verfahren aus
		for (int i = 1; i < 7; i++) {

			if (i == 1) {
				System.out.println("\nVerfahren: 128-bit AES GCM");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
			} else if (i == 2) {
				System.out.println("\nVerfahren: 128-bit AES EAX");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_EAX);
			} else if (i == 3) {
				System.out.println("\nVerfahren: 128-bit AES CTR HMAC SHA256");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
			} else if (i == 4) {
				System.out.println("\nVerfahren: CHACHA 20 POLY 1305");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.CHACHA20_POLY1305);
			} else if (i == 5) {
				System.out.println(" \nVerfahren: 256-bit AES EAX");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_EAX);
			} else if (i == 6) {
				System.out.println("\nVerfahren: 256-bit AES GCM");
				keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
			}
			// initialisierung
			Aead aead = AeadFactory.getPrimitive(keysetHandle);
			// verschlüsselung
			byte[] ciphertextByte = aead.encrypt(plaintextByte, aadtextByte);
			// entschlüsselung
			byte[] decryptedtextByte = aead.decrypt(ciphertextByte, aadtextByte);

			// ausgabe der variablen
			System.out.println("Ausgabe der Variablen");
			System.out.println("plaintextString        :" + plaintextString);
			System.out.println("aadtextString          :" + aadtextString);
			System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
			System.out.println("= = = Verschlüsselung = = =");
			System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
			System.out.println("= = = Entschlüsselung = = =");
			System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
			System.out.println("decryptedtextString    :" + new String(decryptedtextByte));
			// ausgabe des schlüssels
			System.out.println("\nAusgabe des Schlüssels:");
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
			System.out.println(new String(outputStream.toByteArray()));
		}
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