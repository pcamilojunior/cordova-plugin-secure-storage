package com.crypho.plugins;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

public class RSA {
	private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
	private static final Cipher CIPHER = getCipher();

	private static final Object LOCK = new Object();

	public static byte[] encrypt(byte[] buf, String alias) throws Exception {
		synchronized (LOCK) {
			initCipher(Cipher.ENCRYPT_MODE, alias);
			return CIPHER.doFinal(buf);
		}
	}

	public static byte[] decrypt(byte[] encrypted, String alias) throws Exception {
		synchronized (LOCK) {

			initCipher(Cipher.DECRYPT_MODE, alias);
			return CIPHER.doFinal(encrypted);
		}
	}

	public static void createKeyPair(Context ctx, String alias) throws Exception {
		synchronized (LOCK) {
			Calendar notBefore = Calendar.getInstance();

			//this back dates the date of the key in order to avoid some timezone issues found during use with some devices
			notBefore.add(Calendar.HOUR_OF_DAY, -26);
			Calendar notAfter = Calendar.getInstance();
			notAfter.add(Calendar.YEAR, 100);
			String principalString = String.format("CN=%s, OU=%s", alias, ctx.getPackageName());

			if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M){
				KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);
				KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
						.setUserAuthenticationRequired(true)
						//the value used for the validity is 31 days a big number to ensure the keys are always usable after a authentication done by the user
						.setUserAuthenticationValidityDurationSeconds(60*60*24*31)
						.setCertificateSubject(new X500Principal(principalString))
						.setCertificateSerialNumber(BigInteger.ONE)
						.setKeySize(2048)
						.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
						.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
						.setRandomizedEncryptionRequired(true)
						.setKeyValidityStart(notBefore.getTime())
						.setKeyValidityEnd(notAfter.getTime());
				if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.N){
					builder.setInvalidatedByBiometricEnrollment(false);
				}
				KeyGenParameterSpec spec = builder.build();
				generator.initialize(spec);
				generator.generateKeyPair();
			}
			//pre Android 6 key gen
			else{

				KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx)
						.setAlias(alias)
						.setSubject(new X500Principal(principalString))
						.setSerialNumber(BigInteger.ONE)
						.setStartDate(notBefore.getTime())
						.setEndDate(notAfter.getTime())
						.setEncryptionRequired()
						.setKeySize(2048)
						.setKeyType("RSA")
						.build();
				KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER);
				kpGenerator.initialize(spec);
				kpGenerator.generateKeyPair();
			}


		}
	}

	public static void initCipher(int cipherMode, String alias) throws Exception {
		synchronized (LOCK) {
			KeyStore.PrivateKeyEntry keyEntry = getKeyStoreEntry(alias);
			if (keyEntry == null) {
				throw new Exception("Failed to load key for " + alias);
			}
			Key key;
			switch (cipherMode) {
				case Cipher.ENCRYPT_MODE:
					key = keyEntry.getCertificate().getPublicKey();
					break;
				case Cipher.DECRYPT_MODE:
					key = keyEntry.getPrivateKey();
					break;
				default:
					throw new Exception("Invalid cipher mode parameter");
			}

			
			CIPHER.init(cipherMode, key);

		}
	}


	public static boolean isEntryAvailable(String alias) {
		synchronized (LOCK) {
			try {
				return getKeyStoreEntry(alias) != null;
			} catch (Exception e) {
				return false;
			}
		}
	}

	private static KeyStore.PrivateKeyEntry getKeyStoreEntry(String alias) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
		keyStore.load(null, null);
		return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
	}

	private static Cipher getCipher() {
		try {
			return Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (Exception e) {
			return null;
		}
	}

}