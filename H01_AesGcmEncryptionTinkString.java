package net.bplaced.javacrypto.tink;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 22.01.2019
* Funktion: verschlüsselt einen String mit Google Tink AES GCM
* Function: encrypts a String using Google Tink AES GCM
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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;

public final class H01_AesGcmEncryptionTinkString {

	public static void main(String[] args) throws Exception {
		System.out.println("H01 AES GCM Verschlüsselung Tink mit einem String");
		AeadConfig.register();

		String plaintextString = "Das ist der zu verschluesselnde String.";
		String aadtextString = "Hier stehen die AAD-Daten";

		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		byte[] aadtextByte = aadtextString.getBytes("utf-8");

		// schlüssel erzeugen
		KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
		// initialisierung
		Aead aead = AeadFactory.getPrimitive(keysetHandle);
		// verschlüsselung
		byte[] ciphertextByte = aead.encrypt(plaintextByte, aadtextByte);
		// entschlüsselung
		byte[] decryptedtextByte = aead.decrypt(ciphertextByte, aadtextByte);

		// ausgabe der variablen
		System.out.println("\nAusgabe der Variablen");
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("aadtextString          :" + aadtextString);
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + new String(decryptedtextByte));
		
		// veränderung der aadtextByte-Daten führt zu einer Tag mismatch exception
		System.out.println("\nDie Veränderung der AAD-Daten führt zu einer Exception:");
		aadtextByte = new byte[1];
		decryptedtextByte = aead.decrypt(ciphertextByte, aadtextByte);
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