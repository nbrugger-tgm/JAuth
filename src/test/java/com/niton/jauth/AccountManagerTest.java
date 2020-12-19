package com.niton.jauth;

import com.niton.util.Logging;
import com.niton.util.config.Config;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class AccountManagerTest {
	private static List<User> userz = new ArrayList<>();
	private static AccountManager<User,String> manager;

	@BeforeAll
	public static void prep(){
		Logging.init("JAuth Test","logs");
		Config.init("config.cfg");
		manager = new AccountManager<>(new AuthenticationHandler<User,String>() {

			@Override
			public void sendInitPassword(String password) {
				System.out.println("Init pwd : "+password);
			}


			@Override
			public void persistAuthenticateable(User user, byte[] hash) {
				user.hash = hash;
				userz.add(user);
			}

			@Override
			public void deleteAuthenticateable(String id) {
				userz = userz.stream().filter(i -> !i.name.equals(id)).collect(Collectors.toList());
			}

			@Override
			public String getContextID(String context) {
				return context;
			}

			@Override
			public String getContextAuthInfo(String context) {
				return context;
			}

			@Override
			public User getAuthenticateable(String u) {
				return userz.stream().filter(i -> i.name.equals(u)).findFirst().get();
			}

			@Override
			public void onSessionIpPermaBan(String ip) {
				System.out.println("Session perma banned : "+ip);
			}

			@Override
			public void onRapidSessionCheck(String ip, Integer integer) {
				System.out.println("ATTTATCCKKKE : "+ip+" -> "+integer);
			}

			@Override
			public void sendResetTokenMail(String mail, String token) {
				System.out.println("Send "+token+" to "+ mail);
			}

			@Override
			public boolean existsAuthenticatableById(String user) {
				return userz.stream().anyMatch(i->i.name.equals(user));
			}

			@Override
			public byte[] getHash(String user) {
				return getAuthenticateable(user).hash;
			}

			@Override
			public void setHash(String key, byte[] hash) {
				getAuthenticateable(key).hash = hash;
			}
		});
	}


	@Test
	void addAuthenticateable() {
		manager.addAuthenticateable(new User("Nils"), "ich bin kühl");
	}

	@Test
	void deleteUser() {
	}

	@Test
	void authenticate() {
	}

	@Test
	void testAuthenticate() {
	}
	static class User {
		public String name;
		public byte[] hash;

		public User(String nils) {
			name = nils;
		}
	}
}