package com.niton.jauth;

import com.niton.login.Authenticator;

public interface AuthenticationHandler<A,C> {
	/**
	 * Called when an empty password user is added. The random new password should be sent to the user
	 * @param password the random generated password
	 * @param user the authenticateable entity to send the password to
	 */
	void sendInitPassword(String password,A user);

	/**
	 * Should save the user persistently
	 * @param user the object to persist
	 * @param hash the password hash
	 */
	void persistAuthenticateable(A user, byte[] hash);



	/**
	 * removes the user
	 * @param id the unique key of a authenticable object
	 */
	void deleteAuthenticateable(String id);

	/**
	 * Returns a unique value of a context (eg. an IP address)
	 * @param context the context to fetch the value from
	 * @return the unique value
	 */
	String getContextID(C context);

	/**
	 * Get the authentication information from a context
	 * @param context the context to get the auth info from
	 * @return the auth info
	 */
	String getContextAuthInfo(C context);

	/**
	 * Returns the authenticateable persisted object regarding to its ID
	 * @param u the unique field to filter for
	 * @return the authenticateable object
	 */
	A getAuthenticateable(String u);

	/**
	 * Listener for context key banns (due to session related violations)
	 * @param ip the banned context key
	 */
	void onSessionIpPermaBan(String ip);

	/**
	 * Listener for rapid session checking
	 * @param ip the context key of the user
	 * @param integer the done tries by this context
	 */
	void onRapidSessionCheck(String ip, Integer integer);

	/**
	 * Send reset token
	 * @param mail the mail to send to
	 * @param toString the token to send
	 */
	void sendResetTokenMail(String mail, String toString);

	/**
	 * Returns true if the key exist
	 * @param user the unique key of the authenticateable
	 * @return true if it exists
	 */
	boolean existsAuthenticatableById(String user);

	/**
	 * Returns the hash of the given authenticatable object
	 * @param user the id to return the hash for
	 * @return the hash
	 */
	byte[] getHash(String user);

	/**
	 * Updates the password hash of a user
	 * @param key the key of the user to update
	 * @param hash the new hash
	 */
	void setHash(String key, byte[] hash);
}
