package com.otterca.certificateAuthority;

import java.util.List;

import javax.security.cert.Certificate;

/**
 * This service manages the Certificate Authority's internal keystore.
 * <strong>It should never be accessed externally.</strong>
 * 
 * @author Bear Giles <bgiles@coyotesong.com>
 */
public interface KeyStoreService {
	List<String> listKeyAliases();

	Certificate getCertificate(String alias);
	
	boolean isKeyEntry(String alias);

	void createKey(String alias, char[] password);
	
	void deleteKey(String alias, char[] password);
	
	void load(char[] password);
	
	void store(char[] password);
}
