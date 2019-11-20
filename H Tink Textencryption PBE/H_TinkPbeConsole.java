package tinkPbe;

/*
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
import java.security.GeneralSecurityException;
import com.google.crypto.tink.aead.AeadConfig;

public class H_TinkPbeConsole {

	public static void main(String[] args) throws GeneralSecurityException, IOException {
		System.out.println("Tink String Encryption with PBE");

		AeadConfig.register(); // tink initialisation
		TinkPbe tpbe = new TinkPbe(); // tink pbe initialisation

		String plaintextString = "Das ist die zu verschlüsselnde Nachricht. This is the message that needs to get encrypted.";
		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		// das passwort wird z.b. von einem jPassword-Feld übergeben
		char[] passwordChar = "secret Password".toCharArray();
		String ciphertextString = tpbe.encrypt(passwordChar, plaintextString);
		// byte[] decryptedtextByte = tpbe.decrypt(passwordChar, ciphertextString);
		String decryptedtextString = tpbe.decrypt(passwordChar, ciphertextString);
		// ausgabe der variablen
		System.out.println("\nAusgabe der Variablen / Data Output");
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung / Encryption = = =");
		System.out.println("ciphertextString       :" + ciphertextString);
		System.out.println("= = = Entschlüsselung / Decryption = = =");
		System.out.println("decryptedtextString    :" + decryptedtextString);
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