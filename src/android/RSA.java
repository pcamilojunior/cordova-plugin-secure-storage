package com.crypho.plugins;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyNotYetValidException;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
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

			String principalString = String.format("CN=%s, OU=%s", alias, ctx.getPackageName());

			if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
				KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);
				KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
						.setUserAuthenticationRequired(true)
						//the value used for the validity is 31 days a big number to ensure the keys are always usable after a authentication done by the user
						.setUserAuthenticationValidityDurationSeconds(60*60*24*31)
						.setCertificateSubject(new X500Principal(principalString))
						.setCertificateSerialNumber(BigInteger.ONE)
						.setKeySize(2048)
						.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
						.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
						.setRandomizedEncryptionRequired(true)
					    .setInvalidatedByBiometricEnrollment(false);
				if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S){
					builder.setDevicePropertiesAttestationIncluded(false);
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
		initCipher(CIPHER, cipherMode, alias);
	}

	private static void initCipher(Cipher cipher, int cipherMode, String alias) throws Exception {
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

			cipher.init(cipherMode, key);
		}
	}

	public static boolean isEntryAvailable(String alias) throws UserNotAuthenticatedException {
		KeyStore.PrivateKeyEntry entry;

		synchronized (LOCK) {
			try {
				entry = getKeyStoreEntry(alias);
			} catch (Exception e) {
				return false;
			}
		}

		if (entry == null) {
			return false;
		}

		try {
			Cipher tempCipher = getCipher();
			initCipher(tempCipher, Cipher.ENCRYPT_MODE, alias);
			initCipher(tempCipher, Cipher.DECRYPT_MODE, alias);
			return true; // Key is usable
		} catch (UserNotAuthenticatedException e) {
			throw e;
		} catch (KeyNotYetValidException e) {
			return false;
		} catch (KeyPermanentlyInvalidatedException e) {
			// Key is never usable again, so might as well consider it's not available
			// This will let a new one be used in its place
			return false;
		} catch (Exception e) {
			// Keys are currently unavailable but can still be used in the future
			// App may explode but it's ok, as it will conserve data that can be used
			return true;
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