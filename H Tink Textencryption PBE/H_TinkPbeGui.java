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

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import com.google.crypto.tink.aead.AeadConfig;

public class H_TinkPbeGui {

	public static void main(String[] args) throws GeneralSecurityException {
		AeadConfig.register(); // tink initialisation
		TinkPbe tpbe = new TinkPbe(); // tink pbe initialisation

		JFrame f = new JFrame("Text Verschlüsselung mit Google TINK / Text Encryption with Google TINK");
		final JLabel lb1 = new JLabel("Input text:");
		lb1.setBounds(30, 30, 95, 30);
		final JTextArea ta1 = new JTextArea();
		ta1.setBounds(100, 35, 500, 100);
		ta1.setLineWrap(true);
		ta1.setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
		final JLabel lb2 = new JLabel("Password:");
		lb2.setBounds(30, 145, 95, 30);
		final JPasswordField pf = new JPasswordField();
		pf.setBounds(100, 150, 150, 20);
		final JLabel lb3 = new JLabel("Output text:");
		lb3.setBounds(30, 230, 95, 30);
		final JTextArea ta2 = new JTextArea();
		ta2.setBounds(100, 235, 500, 150);
		ta2.setLineWrap(true);
		ta2.setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
		final JLabel lb4 = new JLabel(
				"Created by Michael Fehr http://javacrypto.bplaced.net https://github.com/java-crypto/H-Google-Tink/");
		lb4.setBounds(30, 395, 590, 30);

		JButton encrypt = new JButton("Encrypt");
		encrypt.setBounds(100, 185, 95, 30);
		encrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String ciphertextString = "";
				try {
					ciphertextString = tpbe.encrypt(pf.getPassword(), ta1.getText());
				} catch (GeneralSecurityException | IOException e1) {
					e1.printStackTrace();
					ta2.setText("* * * Error * * *");
				}
				ta2.setText(String.valueOf(ciphertextString));
			}
		});
		JButton decrypt = new JButton("Decrypt");
		decrypt.setBounds(200, 185, 95, 30);
		decrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String decryptedtextString = "";
				try {
					decryptedtextString = tpbe.decrypt(pf.getPassword(), ta1.getText());
					ta2.setText(decryptedtextString);
				} catch (GeneralSecurityException | IOException e1) {
					e1.printStackTrace();
					ta2.setText("* * * Error * * *");
				}

			}
		});
		JButton clear = new JButton("Clear");
		clear.setBounds(300, 185, 95, 30);
		clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ta1.setText("");
				ta2.setText("");
				pf.setText(null);
				ta1.requestFocusInWindow();
			}
		});
		f.add(lb1);
		f.add(ta1);
		f.add(lb2);
		f.add(pf);
		f.add(encrypt);
		f.add(decrypt);
		f.add(clear);
		f.add(lb3);
		f.add(ta2);
		f.add(lb4);
		f.setSize(650, 470);
		f.setLayout(null);
		f.setVisible(true);
	}
}
