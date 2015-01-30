package ru.curs.authserver.logic;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.slf4j.LoggerFactory;

/**
 * Конфигурация подключения к SQL-серверу.
 * 
 */
public final class SQLLoginProvider extends AbstractLoginProvider {

	private static final String USER = "Пользователь '";
	private static final String USER_LOGIN = "Логин пользователя '";
	private static final String ERROR_SQL_SERVER = "Ошибка при работе с базой '%s': %s. Запрос: '%s'";

	private static final MessageDigest MD;
	static {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// Если такое случилось --- у нас Java неправильно стоит...
			e.printStackTrace();
			md = null;
		}
		MD = md;
	}

	// private final Queue<Connection> pool = new LinkedList<Connection>();

	private final Queue<Connection> pool = new ConcurrentLinkedDeque<Connection>();

	private String connectionUsername;
	private String connectionPassword;
	private String table;
	private String fieldLogin;
	private String fieldPassword;
	private String procCheckUser = null;

	private final HashMap<String, String> searchReturningAttributes = new HashMap<String, String>();

	@Override
	void setupLogger(boolean isLogging) {
		if (isLogging) {
			setLogger(LoggerFactory.getLogger(SQLLoginProvider.class));
		}
	}

	void setConnectionUsername(String connectionUsername) {
		this.connectionUsername = connectionUsername;
	}

	void setConnectionPassword(String connectionPassword) {
		this.connectionPassword = connectionPassword;
	}

	void setTable(String table) {
		// this.table = table;
		this.table = table.replace(".", "\".\"");
	}

	void setFieldLogin(String fieldLogin) {
		this.fieldLogin = fieldLogin;
	}

	void setFieldPassword(String fieldPassword) {
		this.fieldPassword = fieldPassword;
	}

	void setProcCheckUser(String procCheckUser) {
		this.procCheckUser = procCheckUser;
	}

	@Override
	void addReturningAttributes(String name, String value) {
		searchReturningAttributes.put(name, value);
	}

	/**
	 * Тип SQL сервера.
	 * 
	 */
	private enum SQLServerType {
		MSSQL, POSTGRESQL, ORACLE
	}

	/**
	 * Возвращает тип SQL сервера.
	 */
	private static SQLServerType getSQLServerType(String url) {
		final String mssql = "sqlserver";
		final String postgresql = "postgresql";
		final String oracle = "oracle";

		SQLServerType st = null;
		if (url.indexOf(mssql) > -1) {
			st = SQLServerType.MSSQL;
		} else {
			if (url.indexOf(postgresql) > -1) {
				st = SQLServerType.POSTGRESQL;
			} else {
				if (url.indexOf(oracle) > -1) {
					st = SQLServerType.ORACLE;
				}
			}
		}

		return st;
	}

	private static Driver registerDriver(String url) throws SQLException {
		Driver result = null;
		if (getSQLServerType(url) == SQLServerType.MSSQL) {
			try {
				result = (Driver) Class.forName(
						"com.microsoft.sqlserver.jdbc.SQLServerDriver")
						.newInstance();
				DriverManager.registerDriver(result);
			} catch (Exception e) {
				throw new SQLException(e);
			}
		}
		if (getSQLServerType(url) == SQLServerType.POSTGRESQL) {
			try {
				result = (Driver) Class.forName("org.postgresql.Driver")
						.newInstance();
				DriverManager.registerDriver(result);
			} catch (Exception e) {
				throw new SQLException(e);
			}
		}
		return result;
	}

	/**
	 * Дерегистрирует драйвера работы с БД.
	 */
	public static Driver unregisterDrivers() {
		Driver result = null;
		while (DriverManager.getDrivers().hasMoreElements()) {
			try {
				result = DriverManager.getDrivers().nextElement();
				DriverManager.deregisterDriver(result);
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return result;
	}

	private synchronized Connection getConnection() throws SQLException {
		// Сначала пытаемся достать коннекшн из пула
		Connection c = pool.poll();
		while (c != null) {
			try {
				if (c.isValid(1)) {
					return c;
				}
			} catch (SQLException e) { // CHECKSTYLE:OFF
				// CHECKSTYLE:ON
			}
			c = pool.poll();
		}

		registerDriver(getConnectionUrl());
		return DriverManager.getConnection(getConnectionUrl(),
				connectionUsername, connectionPassword);
	}

	private static void checkForPossibleSQLInjection(String sql, String errMsg)
			throws EAuthServerLogic {
		if (sql.indexOf(" ") > -1)
			throw EAuthServerLogic.create(errMsg);
	}

	@Override
	void connect(String login, String password, String ip,
			ProviderContextHolder context, PrintWriter pw)
			throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("login='" + login + "'");
		}

		checkForPossibleSQLInjection(login, USER_LOGIN + login + "' в '"
				+ getConnectionUrl() + "' не успешен");

		boolean success = false;
		String message = "";
		String sql = "";
		BadLoginType blt = BadLoginType.BAD_CREDENTIALS;
		try {
			((SQLLink) context).conn = getConnection();

			sql = String.format(
					"SELECT \"%s\", %s FROM \"%s\" WHERE \"%s\" = ?",
					fieldPassword, getSelectFields(), table, fieldLogin);

			PreparedStatement stat = ((SQLLink) context).conn
					.prepareStatement(sql);

			stat.setString(1, login);

			boolean hasResult = stat.execute();
			if (hasResult) {
				ResultSet rs = stat.getResultSet();
				if (rs.next()) {
					String pwd = rs.getString(fieldPassword);
					if ((pwd != null)
							&& (pwd.equals(password) || pwd
									.equals(getHash(password)))) {

						if ((procCheckUser != null) && (ip != null)) {
							CallableStatement cs = ((SQLLink) context).conn
									.prepareCall(String.format(
											"{? = call %s (?, ?, ?)}",
											procCheckUser));

							cs.registerOutParameter(1, java.sql.Types.INTEGER);
							cs.setString(2, login);
							cs.setString(3, ip);
							cs.registerOutParameter(4, java.sql.Types.VARCHAR);

							cs.execute();
							int errorCode = cs.getInt(1);
							if (errorCode == 0) {
								success = true;
								message = USER_LOGIN + login + "' в '"
										+ getConnectionUrl() + "' успешен!";
							} else {
								success = false;
								message = cs.getString(4);
								blt = BadLoginType.BAD_PROC_CHECK_USER;
							}
						} else {
							success = true;
							message = USER_LOGIN + login + "' в '"
									+ getConnectionUrl() + "' успешен!";
						}

					}

					if (success && (pw != null)) {

						String[] attrs = searchReturningAttributes.keySet()
								.toArray(new String[0]);
						XMLStreamWriter xw = XMLOutputFactory.newInstance()
								.createXMLStreamWriter(pw);

						xw.writeStartDocument("utf-8", "1.0");
						xw.writeEmptyElement("user");
						for (String attr : attrs) {
							writeXMLAttr(xw, attr,
									rs.getString(searchReturningAttributes
											.get(attr)));
						}
						xw.writeEndDocument();
						xw.flush();

					}

				}
			}
		} catch (Exception e) {
			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_SQL_SERVER, getConnectionUrl(),
								e.getMessage(), sql));
			}
			throw EAuthServerLogic.create(e);
		}

		if (!success && message.isEmpty()) {
			message = USER_LOGIN + login + "' в '" + getConnectionUrl()
					+ "' не успешен: " + BAD_CREDENTIALS;
		}

		if (getLogger() != null) {
			getLogger().debug(message);
		}

		if (!success) {
			EAuthServerLogic eas = EAuthServerLogic.create(message);
			eas.setBadLoginType(blt);
			throw eas;
		}

	}

	private String getSelectFields() {
		String[] fields = searchReturningAttributes.values().toArray(
				new String[0]);

		String s = null;
		for (String field : fields) {
			field = String.format("\"%s\"", field);
			if (s == null) {
				s = field;
			} else {
				s = s + ", " + field;
			}
		}

		return s;
	}

	@Override
	void getUserInfoByName(ProviderContextHolder context, String name,
			PrintWriter pw) throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("name='" + name + "'");
		}

		checkForPossibleSQLInjection(name, USER + name + "' не найден");

		String sql = "";
		try {
			((SQLLink) context).conn = getConnection();

			sql = String.format("SELECT %s FROM \"%s\" WHERE \"%s\" = ?",
					getSelectFields(), table, fieldLogin);
			PreparedStatement stat = ((SQLLink) context).conn
					.prepareStatement(sql);
			stat.setString(1, name);

			boolean hasResult = stat.execute();
			if (hasResult) {
				ResultSet rs = stat.getResultSet();
				String[] attrs = searchReturningAttributes.keySet().toArray(
						new String[0]);
				XMLStreamWriter xw = XMLOutputFactory.newInstance()
						.createXMLStreamWriter(pw);
				if (rs.next()) {
					xw.writeStartDocument("utf-8", "1.0");
					xw.writeEmptyElement("user");
					for (String attr : attrs) {
						writeXMLAttr(xw, attr,
								rs.getString(searchReturningAttributes
										.get(attr)));
					}
					xw.writeEndDocument();
					xw.flush();

					if (getLogger() != null) {
						getLogger().debug(USER + name + "' найден");
					}

					return;
				}
			}

			if (getLogger() != null) {
				getLogger().debug(USER + name + "' не найден");
			}

		} catch (Exception e) {
			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_SQL_SERVER, getConnectionUrl(),
								e.getMessage(), sql));
			}
			throw EAuthServerLogic.create(e);
		}
	}

	@Override
	void importUsers(ProviderContextHolder context, PrintWriter pw)
			throws EAuthServerLogic {

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
		}

		String sql = "";
		try {
			sql = String.format("SELECT %s FROM \"%s\" ORDER BY \"%s\"",
					getSelectFields(), table, fieldLogin);

			PreparedStatement stat = ((SQLLink) context).conn
					.prepareStatement(sql);

			boolean hasResult = stat.execute();
			if (hasResult) {
				ResultSet rs = stat.getResultSet();
				String[] attrs = searchReturningAttributes.keySet().toArray(
						new String[0]);
				XMLStreamWriter xw = XMLOutputFactory.newInstance()
						.createXMLStreamWriter(pw);
				xw.writeStartDocument("utf-8", "1.0");
				xw.writeStartElement("users");
				while (rs.next()) {
					xw.writeEmptyElement("user");
					for (String attr : attrs) {
						writeXMLAttr(xw, attr,
								rs.getString(searchReturningAttributes
										.get(attr)));
					}
				}
				xw.writeEndDocument();
				xw.flush();
				if (getLogger() != null) {
					getLogger().debug("Импорт пользователей успешно завершен");
				}
			}
		} catch (Exception e) {
			if (getLogger() != null) {
				getLogger().error(
						String.format(ERROR_SQL_SERVER, getConnectionUrl(),
								e.getMessage(), sql));
			}
			throw EAuthServerLogic.create(e);
		}
	}

	@Override
	void changePwd(ProviderContextHolder context, String userName, String newpwd)
			throws EAuthServerLogic {

	}

	@Override
	ProviderContextHolder newContextHolder() {
		return new SQLLink();
	}

	/**
	 * Возвращает значение функции SHA-1 для строки символов в виде 16-ричного
	 * числа, в точности как реализовано в клиентском JavaScript. Необходимо для
	 * контроля логинов и паролей
	 * 
	 * @throws UnsupportedEncodingException
	 */
	private static String getHash(String input)
			throws UnsupportedEncodingException {
		synchronized (MD) {
			MD.reset();
			MD.update(input.getBytes("UTF-8"));
			return asHex(MD.digest());
		}
	}

	/**
	 * Контекст соединения с базой данных.
	 */
	private class SQLLink extends ProviderContextHolder {
		private Connection conn = null;

		@Override
		void closeContext() {
			try {
				if (conn != null && conn.isValid(1))
					pool.add(conn);
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

}
