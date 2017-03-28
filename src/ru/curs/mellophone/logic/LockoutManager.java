package ru.curs.mellophone.logic;

import java.util.HashMap;

/**
 * Класс, обеспечивающий запирание на определённое время пользователя, который
 * несколько раз ввёл неверный пароль.
 */
final class LockoutManager {
	private static final int ATTEMPTS_ALLOWED = 5;
	
	private static long lockoutTime = 10 * 60 * 1000;
	public static void setLockoutTime(long lockoutTime) {
		LockoutManager.lockoutTime = lockoutTime * 60 * 1000;
	}

	private final HashMap<String, LoginCounter> lockouts = new HashMap<String, LoginCounter>();

	/**
	 * Счётчик состояний логина.
	 */
	private static class LoginCounter {
		private int attemptsCount = 0;
		private long lockoutUntil = 0;

		void fail() {
			attemptsCount++;
			if (attemptsCount >= ATTEMPTS_ALLOWED) {
				lockoutUntil = System.currentTimeMillis() + lockoutTime;
			}
		}

		boolean isLocked() {
			// Ещё не навводил много неверных паролей.
			if (attemptsCount < ATTEMPTS_ALLOWED)
				return false;
			// Навводил много неверных, и залочен.
			if (System.currentTimeMillis() <= lockoutUntil)
				return true;
			// Пора разлочить.
			attemptsCount = 0;
			return false;
		}
	}

	/**
	 * Вызывается для проверки, не залочен ли логин.
	 * 
	 * @param login
	 *            логин пользователя.
	 */
	public synchronized boolean isLocked(String login) {
		LoginCounter lc = lockouts.get(login);
		return lc == null ? false : lc.isLocked();
	}

	/**
	 * Вызвается при неверном логине пользователя.
	 * 
	 * @param login
	 *            Логин пользователя.
	 */
	public synchronized void loginFail(String login) {
		LoginCounter lc = lockouts.get(login);
		if (lc == null) {
			lc = new LoginCounter();
			lockouts.put(login, lc);
		}
		lc.fail();
	}

	/**
	 * Успешный логин амнистирует блокировку.
	 * 
	 * @param login
	 *            Логин пользователя.
	 */
	public synchronized void success(String login) {
		lockouts.remove(login);
	}
}
