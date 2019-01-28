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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.StreamingAeadFactory;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;

/**
 * Defines the different sub-commands and their parameters, for command-line
 * invocation.
 */
public final class H05_CommandsDe {
	/** An interface for a command-line sub-command. */
	interface Command {
		public void run() throws Exception;
	}

	static class Options {
		@Option(name = "--keyfile", required = true, usage = "Der Dateiname inkl. Pfad zur Schluesseldatei, wird generiert falls die Datei nicht existiert")
		File keyfile;
		@Option(name = "--in", required = true, usage = "Der Dateiname inkl. Pfad zur Eingabedatei")
		File inFile;
		@Option(name = "--out", required = true, usage = "Der Dateiname inkl. Pfad zur Ausgabedatei")
		File outFile;
		@Option(name = "--aaddata", required = false, usage = "Ergänzende Authentifizierte Daten (AAD) [optional]")
		String aadData;
	}

	/**
	 * Loads a KeysetHandle from {@code keyfile} or generate a new one if it doesn't
	 * exist.
	 */
	private static KeysetHandle getKeysetHandle(File keyfile) throws GeneralSecurityException, IOException {
		if (keyfile.exists()) {
			// Read the cleartext keyset from disk.
			// WARNING: reading cleartext keysets is a bad practice. Tink supports
			// reading/writing
			// encrypted keysets, see
			// https://github.com/google/tink/blob/master/doc/JAVA-HOWTO.md#loading-existing-keysets.
			return CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyfile));
		}
		KeysetHandle keysetHandle = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(keyfile));
		return keysetHandle;
	}

	/**
	 * Reads ciphertext from {@code --in} and shows aad-data if available
	 */
	public static class ShowAadCommand extends Options implements Command {
		@Override
		public void run() throws Exception {
			System.out.println("Modus Show AAD-Data");
			byte[] aadtextByte = null;
			try (FileInputStream fis = new FileInputStream(inFile);
					BufferedInputStream bis = new BufferedInputStream(fis);) {
				// aad-data reader
				byte[] aadtextLengthByte = new byte[4];
				@SuppressWarnings("unused")
				int counter = fis.read(aadtextLengthByte, 0, 4);
				int aadtextLengthInt = byteArrayToInt(aadtextLengthByte);
				aadtextByte = new byte[aadtextLengthInt];
				counter = fis.read(aadtextByte, 0, aadtextLengthInt);
			}
			if (aadtextByte.length > 0) {
				System.out.println("AAD-Data:" + new String(aadtextByte));
			} else {
				System.out.println("Keine AAD-Daten verfügbar.");
			}
		}
	}

	/**
	 * Encrypts a file.
	 */
	public static class EncryptCommand extends Options implements Command {
		@Override
		public void run() throws Exception {
			System.out.println("Modus Verschlüsselung");
			if (inFile.equals(outFile)) {
				System.out.println("Die Eingabe- und Ausgabedatei sind gleich.\n"
						+ "Das Programm würde die Eingabedatei überschreiben,\n"
						+ "daher wird das Programm jetzt beendet");
				System.exit(1);
			}
			byte[] aadtextByte = new byte[0];
			if (aadData != null) {
				aadtextByte = aadData.getBytes("utf-8");
			}
			KeysetHandle keysetHandle = getKeysetHandle(keyfile);
			try (FileInputStream fis = new FileInputStream(inFile);
					BufferedInputStream bis = new BufferedInputStream(fis);
					FileOutputStream out = new FileOutputStream(outFile);
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
				Arrays.fill(buf, (byte) 0); // delete array
			}
			Arrays.fill(aadtextByte, (byte) 0); // delete array
		}
	}

	/**
	 * Decrypts a file.
	 */
	public static class DecryptCommand extends Options implements Command {
		@Override
		public void run() throws Exception {
			System.out.println("Modus Entschlüsselung");
			if (inFile.equals(outFile)) {
				System.out.println("Die Eingabe- und Ausgabedatei sind gleich.\n"
						+ "Das Programm würde die Eingabedatei überschreiben,\n"
						+ "daher wird das Programm jetzt beendet");
				System.exit(1);
			}
			KeysetHandle keysetHandle = getKeysetHandle(keyfile);
			byte[] aadtextByte = null;
			try (FileInputStream fis = new FileInputStream(inFile);
					BufferedInputStream bis = new BufferedInputStream(fis);
					FileOutputStream out = new FileOutputStream(outFile);
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
				Arrays.fill(ibuf,(byte) 0); // array löschen
			}
			if (aadtextByte.length > 0) {
				System.out.println("AAD-Data:" + new String(aadtextByte));
			}
		}
	}

	/**
	 * Converts an Integer to a four Byte long ByteArray.
	 */
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

	/**
	 * Converts a (Four Byte long) Byte Array to an Integer.
	 */
	public static int byteArrayToInt(byte[] b) {
		if (b.length == 4)
			return b[0] << 24 | (b[1] & 0xff) << 16 | (b[2] & 0xff) << 8 | (b[3] & 0xff);
		else if (b.length == 2)
			return 0x00 << 24 | 0x00 << 16 | (b[0] & 0xff) << 8 | (b[1] & 0xff);

		return 0;
	}

	@Argument(metaVar = "encrypt|decrypt|showaad", required = true, handler = SubCommandHandler.class,
			usage = "--keyfile <schluesseldateiname> --in <eingabedateiname> --out <ausgabedateiname>")
	@SubCommands({ @SubCommand(name = "encrypt", impl = EncryptCommand.class),
			@SubCommand(name = "decrypt", impl = DecryptCommand.class),
			@SubCommand(name = "showaad", impl = ShowAadCommand.class) })
	Command command;
}