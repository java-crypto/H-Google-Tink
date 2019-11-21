# H-Google-Tink Text-Verschlüsselung mit Password Based Encryption
Google Tink text encryption using Password Based Encryption

Das Programm mit GUI wird auf der Webseite http://javacrypto.bplaced.net/h-tink-stringverschluesselung-mit-pbe-und-gui/ (Deutsch)
und http://javacrypto.bplaced.net/h-tink-string-encryption-using-pbe-and-gui/ (Englisch) erklärt. 

Die deutsche Beschreibung für die Konsolenanwendung findet Ihr auf der Webseite 
http://javacrypto.bplaced.net/h-tink-stringverschluesselung-mit-pbe-konsole/

The GUI-version is explained on my website http://javacrypto.bplaced.net/h-tink-stringverschluesselung-mit-pbe-und-gui/ (German)
and http://javacrypto.bplaced.net/h-tink-string-encryption-using-pbe-and-gui/ (English). 

The Explanation for the console-version is available under 
http://javacrypto.bplaced.net/h-tink-stringverschluesselung-mit-pbe-konsole/ (German only).

Die Einbindung der Java Klasse TinkPbe.java erfolgt mit 4 Zeilen Programmcode:
  AeadConfig.register(); // tink initialisation
	TinkPbe tpbe = new TinkPbe(); // tink pbe initialisation
	String ciphertextString = tpbe.encrypt(passwordChar, plaintextString); // encryption
	String decryptedtextString = tpbe.decrypt(passwordChar, ciphertextString); // decryption



* Sicherheitshinweis * Einige Programme sind kryptographisch nicht sicher und sollten nicht für den Produktiveinsatz genutzt werden, sie werden hier nur zu Lern- und Lehrzwecken bereitgestellt. 

Alle Programme sind sowohl unter Java 8 als auch unter Java 11 lauffähig.

Website: http://javacrypto.bplaced.net The programs in this area show examples of uses the crypto library Google Tink.

* Security notice * Some program are cryptographic unsafe and should not used in any production case, they are provided for learning purposes only. 

All programms are runnable with Java 8 and Java 11.
