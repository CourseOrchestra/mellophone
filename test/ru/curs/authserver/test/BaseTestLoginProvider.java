package ru.curs.authserver.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.Before;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Базовый класс для тестов LoginProvider'ов.
 */
public class BaseTestLoginProvider {

	private static final String SES_ID = "357deea02b6263912cc33e28c56e9382";

	private String login;
	private String password;
	private String checkname;

	/**
	 * Устанавливает login.
	 * 
	 * @param login
	 *            login
	 * 
	 */
	protected void setLogin(String login) {
		this.login = login;
	}

	/**
	 * Устанавливает password.
	 * 
	 * @param password
	 *            password
	 * 
	 */
	protected void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Устанавливает checkname.
	 * 
	 * @param checkname
	 *            checkname
	 * 
	 */
	protected void setCheckname(String checkname) {
		this.checkname = checkname;
	}

	/**
	 * Перед началом logout.
	 */
	@Before
	public void beforeTest() {
		try {
			AuthManager.getTheManager().logout(SES_ID);
		} catch (EAuthServerLogic e) {
			e.printStackTrace();
		}
	}

	/**
	 * Тест ф-ции login.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void login() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);
	}

	/**
	 * Тест1 ф-ции isAuthenticated.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void isAuthenticated1() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		AuthManager.getTheManager().isAuthenticated(SES_ID, null, pw);
		assertTrue(sw.toString().indexOf(login) > 0);
	}

	/**
	 * Тест2 ф-ции isAuthenticated.
	 * 
	 */
	protected void isAuthenticated2() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		try {
			AuthManager.getTheManager().isAuthenticated(SES_ID, null, pw);
		} catch (EAuthServerLogic e) {
			assertTrue(e.getMessage().indexOf("не аутентифицирована") > 0);
		}
	}

	/**
	 * Тест ф-ции logout.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void logout() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		AuthManager.getTheManager().isAuthenticated(SES_ID, null, pw);
		assertTrue(sw.toString().indexOf(login) > 0);

		AuthManager.getTheManager().logout(SES_ID);

		try {
			AuthManager.getTheManager().isAuthenticated(SES_ID, null, pw);
		} catch (EAuthServerLogic e) {
			assertTrue(e.getMessage().indexOf("не аутентифицирована") > 0);
		}
	}

	/**
	 * Тест1 ф-ции checkName.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void checkName1() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		AuthManager.getTheManager().checkName(SES_ID, checkname, pw);
		assertTrue(sw.toString().indexOf(checkname) > 0);
	}

	/**
	 * Тест2 ф-ции checkName.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void checkName2() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		AuthManager.getTheManager().checkName(SES_ID, checkname, pw);
		assertTrue(sw.toString().indexOf(checkname) == -1);
	}

	/**
	 * Тест1 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void authenticationGif1() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		String s = AuthManager.getTheManager().authenticationGif("", authsesid);
		assertEquals("AUTH_OK", s);
	}

	/**
	 * Тест2 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void authenticationGif2() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		String s = AuthManager.getTheManager().authenticationGif(SES_ID, "");
		assertNotNull(s);
	}

	/**
	 * Тест3 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void authenticationGif3() throws EAuthServerLogic {
		String s = AuthManager.getTheManager().authenticationGif(SES_ID, "");
		assertNull(s);
	}

	/**
	 * Тест ф-ции importUsers.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	protected void importUsers() throws EAuthServerLogic {
		String authsesid = AuthManager.getTheManager().login(SES_ID,
				"group_providers", login, password, null);
		assertNotNull(authsesid);

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		AuthManager.getTheManager().importUsers(SES_ID, pw);
		assertTrue(sw.toString().indexOf(login) > 0);
	}

}
