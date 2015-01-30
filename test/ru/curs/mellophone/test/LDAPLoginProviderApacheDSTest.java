package ru.curs.mellophone.test;

import org.junit.Test;

import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Тесты LDAPLoginProvider для ApacheDS.
 */
public class LDAPLoginProviderApacheDSTest extends BaseTestLoginProvider {

	private static final String LOGIN = "ПетровApache";
	private static final String PASSWORD = "пасс2";

	private static final String CHECKNAME_EXISTS = "СидоровApache";
	private static final String CHECKNAME_NOT_EXISTS = "СидоровApache22";

	/**
	 * Тест ф-ции login.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testLogin() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		login();
	}

	/**
	 * Тест1 ф-ции isAuthenticated.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testIsAuthenticated1() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		isAuthenticated1();
	}

	/**
	 * Тест2 ф-ции isAuthenticated.
	 * 
	 */
	@Test
	public void testIsAuthenticated2() {
		isAuthenticated2();
	}

	/**
	 * Тест ф-ции logout.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testLogout() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		logout();
	}

	/**
	 * Тест1 ф-ции checkName.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testCheckName1() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);
		setCheckname(CHECKNAME_EXISTS);

		checkName1();
	}

	/**
	 * Тест2 ф-ции checkName.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testCheckName2() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);
		setCheckname(CHECKNAME_NOT_EXISTS);

		checkName2();
	}

	/**
	 * Тест1 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testAuthenticationGif1() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		authenticationGif1();
	}

	/**
	 * Тест2 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testAuthenticationGif2() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		authenticationGif2();
	}

	/**
	 * Тест3 ф-ции authenticationGif.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testAuthenticationGif3() throws EAuthServerLogic {
		authenticationGif3();
	}

	/**
	 * Тест ф-ции importUsers.
	 * 
	 * @throws EAuthServerLogic
	 *             EAuthServerLogic
	 */
	@Test
	public void testImportUsers() throws EAuthServerLogic {
		setLogin(LOGIN);
		setPassword(PASSWORD);

		importUsers();
	}

}
