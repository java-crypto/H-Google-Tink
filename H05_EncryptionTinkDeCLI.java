package net.bplaced.javacrypto.tink;
/*
 * Copyright (c) 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright: Dieses Programm ist unter der Apache Lizenz Version 2.0 freigegeben
* Copyright: This software is released under Apache License Version 2.0.
* Lizenztext/Licence: <http://www.apache.org/licenses/LICENSE-2.0>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 26.01.2019
* Funktion: verschlüsselt Dateien und AAD-Daten mit Google Tink Streaming AES GCM 256 Bit
* Function: encrypts files and aad-data using Google Tink Streaming AES GCM 256 Bit
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
* jar-Datei: https://mvnrepository.com/artifact/args4j/args4j args4j-2.33.jar 
* jar-Datei: https://mvnrepository.com/artifact/org.json/json
*/

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import com.google.crypto.tink.config.TinkConfig;

/**
 * A command-line tool that can encrypt and decrypt large files with
 * StreamingAead AES256-GCM.
 *
 * <p>
 * This application uses the <a href="https://github.com/google/tink">Tink<a/>
 * crypto library.
 */
public final class H05_EncryptionTinkDeCLI {

	public static void main(String[] args) throws Exception {
		// Beispiel für Verschlüsselung: 
		// encrypt --keyfile myOwnEncryption.key --in plaintext.txt --out ciphertext.txt
		// Beispiel für Verschlüsselung mit AAD-Daten:
		// encrypt --keyfile myOwnEncryption.key --in plaintext.txt --out ciphertext.txt --aaddata "Das sind meine AAD-Daten"
		// Beispiel für Entschlüsselung:
		// decrypt --keyfile myOwnEncryption.key --in ciphertext.txt --out decryptedtext.txt
		// Beispiel für die Anzeige der AAD-Daten
		// showaad --in ciphertext.txt --keyfile null --out null
		
		TinkConfig.register();
		System.out.println("Programm H05 Encryption Tink DE CLI");
		System.out.println("Source: http://javacrypto.bplaced.net https://github.com/java-crypto/H-Google-Tink");

		// checks for unlimited encryption
		if (restrictedCryptography() == true) {
			System.out.println("Ihre Java-Version unterstützt nur 128 Bit Schlüssel (eingeschränkte Kryptographie).");
			System.out.println("Das Programm kann nicht ausgeführt werden, bitte lassen Sie die uneingeschränkte\n"
					+ "Kryptographie freischalten.\nDas Programm wird jetzt beendet.");
			System.exit(1);
		}

		H05_CommandsDe commands = new H05_CommandsDe();
		CmdLineParser parser = new CmdLineParser(commands);
		try {
			parser.parseArgument(args);
		} catch (CmdLineException e) {
			System.out.println(e);
			e.getParser().printUsage(System.out);
			System.exit(1);
		}
		try {
			commands.command.run();
		} catch (GeneralSecurityException e) {
			System.out.println(
					"Fehler bei der Ver- oder Entschlüsselung - Cannot encrypt or decrypt, got error: " + e.toString());
			System.exit(1);
		}
		System.out.println("Programm H05 Encryption Tink CLI beendet");
	}

	/**
	 * Determines if cryptography restrictions apply. Restrictions apply if the
	 * value of {@link Cipher#getMaxAllowedKeyLength(String)} returns a value
	 * smaller than {@link Integer#MAX_VALUE} if there are any restrictions
	 * according to the JavaDoc of the method. This method is used with the
	 * transform <code>"AES/CBC/PKCS5Padding"</code> as this is an often used
	 * algorithm that is <a href=
	 * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl">an
	 * implementation requirement for Java SE</a>.
	 * 
	 * @return <code>true</code> if restrictions apply, <code>false</code> otherwise
	 */
	public static boolean restrictedCryptography() {
		try {
			return Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Integer.MAX_VALUE;
		} catch (final NoSuchAlgorithmException e) {
			throw new IllegalStateException(
					"The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)",
					e);
		}
	}
}