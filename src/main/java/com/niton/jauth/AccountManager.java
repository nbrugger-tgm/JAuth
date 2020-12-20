package com.niton.jauth;

import java.nio.charset.StandardCharsets;
import java.util.*;

import com.niton.jauth.config.AuthConfig;
import com.niton.login.Authenticator;
import com.niton.login.LoginHandler;
import com.niton.login.LoginResult;
import com.niton.login.cfg.LoginSecurityConfig;
import com.niton.util.Logging;
import com.niton.util.config.Config;
import org.jasypt.util.password.BasicPasswordEncryptor;

/**
 * Enables user interaction with the Database
 */
public class AccountManager<A,C> implements Authenticator<String> {
	/**
	 * The list of all the blocked account
	 * KEY   : The email of the blocked user
	 * VALUE : The time at which the account was blocked
	 */
	private HashMap<String,Long> accountBlocks = new HashMap<>();
	/**
	 * The list of blocked IPs which are blocked because they tried to login with a bad session key
	 * Key: the blocked IP
	 * Value: the time of the block
	 */
	private HashMap<String,Long> sessionIpBlocks = new HashMap<>();

	/**
	 * The session keys expiration time
	 * key: session key
	 * value: the time the key was created
	 */
	private HashMap<String,Long> creationTime = new HashMap<>();

	/**
	 * The number of guesses the user had already done at login
	 * key: user email
	 * value: the number of password guesses
	 */
	private HashMap<String, Integer> tries = new HashMap<>();

	/**
	 * The number of guesses the IP had already done at a session key
	 * key: ip address
	 * value: the number of key guesses
	 */
	private HashMap<String, Integer> sessionTries = new HashMap<>();


	/**
	 * The information which token belongs to which user
	 * key: session key
	 * value: user email
	 */
	private HashMap<String,String> token = new HashMap<>();
	/**
	 * the same as {@link AccountManager#token} but key and value is switched
	 */
	private HashMap<String,String> reverseTokens = new HashMap<>();

	/**
	 * The last time (value) the token (key) was guessed
	 */
	private HashMap<String,Long> tokenTime = new HashMap<>();

	private LoginHandler<String> handler;

//	private static char[] allowedKeySymbols = "1234567890!\"§$%&/()=?\\;,.:<>|-_+*~#qwertzuioplkjhgfdsaxcvbnmQWERTZUIOPASDFGHJKLYXCVBNM".toCharArray();
	private char[] allowedKeySymbols = "1234567890!-_+#qwertzuioplkjhgfdsaxcvbnmQWERTZUIOPASDFGHJKLYXCVBNM".toCharArray();
	private char[] tokensym = "1234567890QWERTZUIOPASDFGHJKLYXCVBNM".toCharArray();

	private HashMap<String,Long> lastLoginAttempt = new HashMap<>();
	private final AuthenticationHandler<A,C> auther;
	private static final BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
	private boolean supportRandomInitPassword = true;
	public AccountManager(AuthenticationHandler<A,C> auther){
		handler = new LoginHandler<>(new LoginSecurityConfig(com.niton.util.config.Config.cfg), this);
		this.auther = auther;
	}

	/**
	 * Creates a kind of hash from the password, which only can be checked for equality with te @see {@link AccountManager#checkHash(byte[], String)}
	 * @param password the password to create the hash of
	 * @return the hash as byte[]
	 */
	public static byte[] hash(String password){
		return passwordEncryptor.encryptPassword(password).getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Evaluates if the hash is the hash from the password
	 * @param hash the hash obtained by {@link AccountManager#hash(String)}
	 * @param password the password to check against
	 * @return true if the hash was generated from the same password
	 */
	private static boolean checkHash(byte[] hash,String password){
		return passwordEncryptor.checkPassword(password,new String(hash,StandardCharsets.UTF_8));
	}

	/**
	 * Adds a user and sets the password or sends a password email
	 * @param user the user object to add
	 * @param password the password to set for the user or if it is <b>null</b> a random password is generated and sent to the user by email
	 */
	public void addAuthenticateable(A user, String password) {
		Logging.log(Logging.LogContext.SECURITY, "Create Account");
		if(password == null) {
			if (supportRandomInitPassword) {
				Logging.log(Logging.LogContext.SECURITY, "Generate random user password");
				password = getRandomID(8, 10);
				auther.sendInitPassword(password,user);
			}else
				throw new UnsupportedOperationException("Cannot add no password user without supportRandomInitPassword");
		}
		auther.persistAuthenticateable(user,hash(password));
	}

	/**
	 * removes the user
	 * @param id the unique key of a authenticable object
	 */
	public void deleteUser(String id) {
		auther.deleteAuthenticateable(id);
		tries.remove(id);
		reverseTokens.remove(id);
	}

	/**
	 * Deletes all hash maps wich renders all sessions invalid and revokes all blocked ips and users
	 */
	public void clearAllIDs(){
		sessionIpBlocks.clear();
		accountBlocks.clear();
		creationTime.clear();
		token.clear();
		reverseTokens.clear();
	}

	/**
	 * Change or set the id of a user
	 * @param email the user to set the id for
	 * @param ID the session key
	 */
	public void setUserID(String email,String ID){
		creationTime.put(ID, System.currentTimeMillis());
		token.put(ID,email);
		reverseTokens.put(email, ID);
	}

	/**
	 * get the authenticated object in a certain context
	 * @param context the context wich identifies an authenticated object (could be an web request or a cookie)
	 * @return the authenticated object
	 */
	public A getAuthentication(C context) {
		String ip = auther.getContextID(context);

		if(!checkIp(ip))
			return null;

		String key = auther.getContextAuthInfo(context);

		String u = getEmail(key);

		if(u == null){
			sessionTries.put(ip, (sessionTries.containsKey(ip) ? (sessionTries.get(ip)+1) : 1));
			sessionIpBlocks.put(ip, System.currentTimeMillis());
		}else{
			if(creationTime.containsKey(key) && System.currentTimeMillis()-creationTime.get(key) > 1000L *60* new AuthConfig(Config.cfg).security.session.valid_for) {
				token.remove(key);
				reverseTokens.remove(u);
				return null;
			}
			sessionTries.remove(ip);
			sessionIpBlocks.remove(ip);
		}
		if(auther.existsAuthenticatableById(u))
			return auther.getAuthenticateable(u);
		else
			return null;
	}

	private boolean checkIp(String ip) {
		//                                     is ban active/expired
		AuthConfig authConf = new AuthConfig(Config.cfg);
		if(sessionIpBlocks.containsKey(ip) && (((sessionIpBlocks.get(ip)+authConf.security.session.ip_ban.duration)-System.currentTimeMillis())>=0)){
			long newTime;
			if(authConf.security.session.ip_ban.cumulative){
				newTime = sessionIpBlocks.get(ip);
				newTime += authConf.security.session.ip_ban.duration;
				if(authConf.security.session.ip_ban.cumulative_max != -1){
					newTime = Math.min(newTime, System.currentTimeMillis()+ authConf.security.session.ip_ban.cumulative_max);
				}
				Logging.log(Logging.Level.WARNING, Logging.LogContext.SECURITY,"IP-Ban for \""+ip+"\" extended to " + (newTime-System.currentTimeMillis())/1000 +"s (Session guessing)");
			}else{
				newTime = System.currentTimeMillis()+ authConf.security.session.ip_ban.duration;
				Logging.log(Logging.Level.WARNING, Logging.LogContext.SECURITY,"IP-Ban for \""+ip+"\" refilled to " + (newTime-System.currentTimeMillis())/1000 +"s (Session guessing)");
			}
			sessionIpBlocks.put(ip, newTime);
			auther.onRapidSessionCheck(ip,sessionTries.get(ip));
			return false;
		}else if(sessionIpBlocks.containsKey(ip)){
			sessionIpBlocks.remove(ip);
			Logging.log(Logging.LogContext.SECURITY,"IP-Ban ("+ip+") expired");
		}
		if(sessionTries.containsKey(ip) && sessionTries.get(ip) > authConf.security.session.ip_ban.perma_ban_on) {
			auther.onSessionIpPermaBan(ip);
			sessionTries.put(ip, (int) (authConf.security.session.ip_ban.perma_ban_on*0.75));
			sessionIpBlocks.put(ip,System.currentTimeMillis()+(authConf.security.perma_duration));
			return false;
		}
		return true;
	}


	/**
	 * Get the users email by its session key
	 * @param id session/api key
	 * @return the users email
	 */
	public String getEmail(String id){
		return token.get(id);
	}

	/**
	 * Loggin attempt<br>
	 * Rules : <br>
	 *     <ul>
	 *         <li>Maximum 5 tries</li>
	 *         <li>2 seconds between each guess</li>
	 *     </ul>
	 * @param name the email of the user
	 * @param pwd the password to check again
	 * @return true if the login was successful
	 */
	public LoginResult authenticate(String name, String pwd, String ip) {
		LoginResult res = handler.handle(name, pwd, ip);
		if(res.success)
			setUserID(name, getRandomID(63, 72));
		return res;
	}

	/**
	 * Get the id of the user
	 * @param name email of the user
	 * @return the api key of the user
	 */
	public String getID(
			String name
	) {
		String key = reverseTokens.get(name);
		if(key != null)
			return key;
		key = getRandomID(63, 72);
		token.put(key, name);
		reverseTokens.put(name, key);
		creationTime.put(key, System.currentTimeMillis());
		return key;
	}

	/**
	 * random lenght id generator
	 * @param from minimum length
	 * @param to maximum lenght
	 * @return the generated id
	 */
	private String getRandomID(int from, int to){
		Random r = new Random();
		StringBuilder builder = new StringBuilder();
		int len = r.nextInt(to-from)+from;
		for(int i = 0;i<len;i++)
			builder.append(allowedKeySymbols[Math.abs(r.nextInt()%allowedKeySymbols.length)]);
		return builder.toString();
	}

	public boolean sendToken(String mail) {
		StringBuilder token = null;
		if(reverseTokens.containsKey(mail)){
			if(System.currentTimeMillis() - tokenTime.get(reverseTokens.get(mail)) < 10*60*1000)
				return false; //man kann anscheinend nur alle 10 min eine mail senen
			token = new StringBuilder(reverseTokens.get(mail));
			tokenTime.put(token.toString(), System.currentTimeMillis());
		}
		if(token == null){
			token = new StringBuilder();
			for (int i = 0;i<7;i++){
				token.append(tokensym[(int) (Math.random() * tokensym.length)]);
			}
		}
		tokenTime.put(token.toString(), System.currentTimeMillis());
		this.token.put(token.toString(), mail);
		reverseTokens.put(mail, token.toString());
		auther.sendResetTokenMail(mail,token.toString());
		return true;
	}


	public boolean isCorrectToken(String mail, String token) {
		//TODO: settings
		return this.token.containsKey(token) && this.token.get(token).equals(mail) && System.currentTimeMillis()-tokenTime.get(token)<30*60*1000;
	}


	public void setPassword(String mail, String newPassword) {
		auther.setHash(mail,hash(newPassword));
		String token = reverseTokens.remove(mail);
		this.token.remove(token);
	}

    public void logout(String id) {
		tries.remove(getEmail(id));
		reverseTokens.remove(getEmail(id));
		token.remove(id);
    }

	@Override
	public boolean authenticate(String user, String password) {
		if(!auther.existsAuthenticatableById(user))
			return false;
		return checkHash(auther.getHash(user), password);
	}

	public boolean isSupportRandomInitPassword() {
		return supportRandomInitPassword;
	}

	public void setSupportRandomInitPassword(boolean supportRandomInitPassword) {
		this.supportRandomInitPassword = supportRandomInitPassword;
	}
}
