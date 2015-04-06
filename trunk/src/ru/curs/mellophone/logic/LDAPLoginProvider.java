package ru.curs.mellophone.logic;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.slf4j.LoggerFactory;

/**
 * Конфигурация подключения к LDAP-серверу.
 * 
 */
final class LDAPLoginProvider extends AbstractLoginProvider {

	private static final String USER_NOT_FOUND = "Пользователь %s не найден в директории.";

	private static final String ATTR_SID = "SID";

	private static final String ATTR_NOT_DEFINED = "";

	static {
		// Выставляем свойства подключения к файлам Kerberos
		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();

		String sKerberosAuthLoginConfig;
		String sKerberosKrb5Conf;
		if (classLoader.getResource(AuthManager.DIR_CONFIG + "jaas.txt") != null) {
			sKerberosAuthLoginConfig = classLoader.getResource(
					AuthManager.DIR_CONFIG + "jaas.txt").getFile();
			System.setProperty("java.security.auth.login.config",
					sKerberosAuthLoginConfig);
		}
		if (classLoader.getResource(AuthManager.DIR_CONFIG + "krb.txt") != null) {
			sKerberosKrb5Conf = classLoader.getResource(
					AuthManager.DIR_CONFIG + "krb.txt").getFile();

			System.setProperty("java.security.krb5.conf", sKerberosKrb5Conf);
		}
	}

	/**
	 * Тип LDAP-сервера.
	 * 
	 */
	enum ServerType {
		MSActiveDirectory, ApacheDS
	}

	/**
	 * Определяет различные типы аутентификации.
	 * 
	 * 
	 */
	enum SecurityAuthenticationType {
		/**
		 * satNone - проверка имени пользователя и пароля не производится (мб
		 * полезна, если сервер допускает анонимные коннекты).
		 */
		None,

		/**
		 * satSimple - пароль передается в незашифрованном виде.
		 */
		Simple,

		/**
		 * пароль передается в зашифрованном виде, используя алгортим
		 * DIGEST_MD5.
		 * 
		 * Замечания по поводу аутентификации при помощи DIGEST_MD5: 1.В случае
		 * AD Windows необходимо, чтобы имя пользователя было sAMAccountName
		 * 2.Критические системные объекты (например, 'Administrator')
		 * использовать нельзя 3.В случае AD Windows 2000 необходимо, чтобы на
		 * сервере было установлено "reversible password encryption enabled"
		 */
		DIGEST_MD5,

		/**
		 * аутентификация при помощи Kerberos.
		 */
		GSSAPI
	}

	private ServerType servertype;
	private boolean usessl;
	private SecurityAuthenticationType sat;
	private final List<String> searchBases = new LinkedList<String>();
	private final HashMap<String, String> searchReturningAttributes = new HashMap<String, String>();
	private String searchFilterForUser;
	private String searchFilterForImport;
	private String domainName = null;

	private class InitialKerberosContext implements
			java.security.PrivilegedAction<Object> {
		private final LDAPLink ldapLink;

		public InitialKerberosContext(LDAPLink ldapLink) {
			this.ldapLink = ldapLink;
		}

		@Override
		public Object run() {
			createInitialKerberosContext();
			return null;
		}

		private void createInitialKerberosContext() {
			Hashtable<String, Object> ldapParams = new Hashtable<String, Object>(
					12);
			ldapParams.put("java.naming.ldap.version", "3");
			ldapParams.put("java.naming.factory.initial",
					"com.sun.jndi.ldap.LdapCtxFactory");
			if ((servertype == ServerType.MSActiveDirectory)
					&& (searchReturningAttributes.get(ATTR_SID) != null)) {
				ldapParams.put("java.naming.ldap.attributes.binary",
						searchReturningAttributes.get(ATTR_SID));
			}
			ldapParams.put("java.naming.referral", "follow");
			ldapParams.put("java.naming.provider.url", getConnectionUrl());
			if (usessl)
				ldapParams.put(Context.SECURITY_PROTOCOL, "ssl");
			ldapParams.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

			ldapParams.put("javax.security.sasl.qop", "auth-conf");
			ldapParams.put("javax.security.sasl.strength", "high");

			try {
				ldapLink.ctx = new InitialLdapContext(ldapParams, null);
			} catch (NamingException e) {
				e.printStackTrace();
			}
		}
	}

	private class KerberosCallbackHandler implements CallbackHandler {
		private final String sSecurityPrincipal;
		private final String sSecurityCredentials;

		public KerberosCallbackHandler(String sSecurityPrincipal,
				String sSecurityCredentials) {
			this.sSecurityPrincipal = sSecurityPrincipal;
			this.sSecurityCredentials = sSecurityCredentials;
		}

		@Override
		public void handle(Callback[] callbacks) throws java.io.IOException,
				UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					NameCallback cb = (NameCallback) callbacks[i];
					cb.setName(sSecurityPrincipal);

				} else if (callbacks[i] instanceof PasswordCallback) {
					PasswordCallback cb = (PasswordCallback) callbacks[i];

					char[] passwd = new char[sSecurityCredentials.length()];
					sSecurityCredentials.getChars(0, passwd.length, passwd, 0);

					cb.setPassword(passwd);
				} else {
					throw new UnsupportedCallbackException(callbacks[i]);
				}
			}
		}
	}

	@Override
	void setupLogger(boolean isLogging) {
		if (isLogging) {
			setLogger(LoggerFactory.getLogger(LDAPLoginProvider.class));
		}
	}

	public void setServertype(ServerType servertype) {
		this.servertype = servertype;
	}

	void setUsessl(boolean usessl) {
		this.usessl = usessl;
	}

	void setSat(SecurityAuthenticationType sat) {
		this.sat = sat;
	}

	void addSearchBase(String sb) {
		searchBases.add(sb);
	}

	@Override
	void addReturningAttributes(String name, String value) {
		searchReturningAttributes.put(name, value);
	}

	void setSearchFilterForUser(String searchFilterForUser) {
		this.searchFilterForUser = searchFilterForUser;
	}

	void setSearchFilterForImport(String searchFilterForImport) {
		this.searchFilterForImport = searchFilterForImport;
	}

	private static String convertSIDToString(byte[] sID) {
		// Add the 'S' prefix
		StringBuilder strSID = new StringBuilder("S-");

		// bytes[0] : in the array is the version (must be 1 but might
		// change in the future)
		strSID.append(sID[0]).append('-');

		// bytes[2..7] : the Authority
		StringBuilder tmpBuff = new StringBuilder();
		for (int t = 2; t <= 7; t++) {
			String hexString = Integer.toHexString(sID[t] & 0xFF);
			tmpBuff.append(hexString);
		}
		strSID.append(Long.parseLong(tmpBuff.toString(), 16));

		// bytes[1] : the sub authorities count
		int count = sID[1];

		// bytes[8..end] : the sub authorities (these are Integers - notice
		// the endian)
		for (int i = 0; i < count; i++) {
			int currSubAuthOffset = i * 4;
			tmpBuff.setLength(0);
			tmpBuff.append(String.format("%02X%02X%02X%02X",
					sID[11 + currSubAuthOffset] & 0xFF,
					sID[10 + currSubAuthOffset] & 0xFF,
					sID[9 + currSubAuthOffset] & 0xFF,
					sID[8 + currSubAuthOffset] & 0xFF));

			strSID.append('-').append(Long.parseLong(tmpBuff.toString(), 16));
		}

		// That's it - we have the SID
		return strSID.toString();
	}

	private String getConnectName(String name) throws EAuthServerLogic {
		switch (servertype) {
		case MSActiveDirectory:
			name = getConnectNameForMSActiveDirectory(name);
			break;
		case ApacheDS:
			name = getConnectNameForApacheDS(name);
			break;
		}

		return name;
	}

	private String getConnectNameForMSActiveDirectory(String name) {
		// if ((sat == SecurityAuthenticationType.DIGEST_MD5)
		// || (sat == SecurityAuthenticationType.GSSAPI)) {
		if (name.indexOf("\\") > -1)
			name = name.substring(name.lastIndexOf("\\") + 1);
		if (name.indexOf("@") > -1)
			name = name.substring(0, name.lastIndexOf("@"));
		// }

		return name;
	}

	private Hashtable<String, Object> createLdapParamsForApacheDS() {
		Hashtable<String, Object> ldapParams = new Hashtable<String, Object>(12);
		ldapParams.put("java.naming.ldap.version", "3");
		ldapParams.put("java.naming.factory.initial",
				"com.sun.jndi.ldap.LdapCtxFactory");
		ldapParams.put("java.naming.referral", "follow");
		ldapParams.put("java.naming.provider.url", getConnectionUrl());
		if (usessl)
			ldapParams.put(Context.SECURITY_PROTOCOL, "ssl");
		ldapParams.put(Context.SECURITY_AUTHENTICATION, "simple");

		return ldapParams;
	}

	private String getConnectNameForApacheDS(String name)
			throws EAuthServerLogic {

		try {
			InitialLdapContext ctx = new InitialLdapContext(
					createLdapParamsForApacheDS(), null);

			NamingEnumeration<SearchResult> searchResults;

			String searchName = getSearchName(name);
			String searchFilter = String
					.format(searchFilterForUser, searchName);

			if (getLogger() != null) {
				getLogger().debug("Url='" + getConnectionUrl() + "'");
				getLogger().debug("searchName='" + name + "'");
				getLogger().debug("searchFilter='" + searchFilter + "'");
			}

			SearchControls ldapSearchCtrls = new SearchControls();
			ldapSearchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			ldapSearchCtrls.setReturningAttributes(new String[0]);
			ldapSearchCtrls.setReturningObjFlag(true);

			name = null;
			for (String sSearchBase : searchBases) {

				if (getLogger() != null) {
					getLogger().debug("sSearchBase='" + sSearchBase + "'");
				}

				searchResults = ctx.search(sSearchBase, searchFilter,
						ldapSearchCtrls);
				if (searchResults.hasMoreElements()) {
					name = searchResults.next().getNameInNamespace();

					if (getLogger() != null) {
						getLogger().debug(
								"Пользователь '" + searchName
										+ "' найден в sSearchBase='"
										+ sSearchBase + "'. DN = '" + name
										+ "'");
					}

					break;
				}
			}
			if (name == null) {

				if (getLogger() != null) {
					getLogger()
							.error(String.format(USER_NOT_FOUND, searchName));
				}

				throw EAuthServerLogic.create(String.format(USER_NOT_FOUND,
						searchName));
			}
		} catch (NamingException e) {

			if (getLogger() != null) {
				getLogger().debug("Url='" + getConnectionUrl() + "'");
				getLogger().error(String.format(e.getMessage()));
			}

			throw EAuthServerLogic.create(e);
		}

		return name;
	}

	private String getSearchName(String name) {
		// if ((servertype == ServerType.MSActiveDirectory)
		// && (name.indexOf("\\") > -1)) {
		// name = name.substring(name.lastIndexOf("\\") + 1);
		// }

		if (servertype == ServerType.MSActiveDirectory) {
			name = getConnectNameForMSActiveDirectory(name);
		}

		return name;
	}

	private Hashtable<String, Object> createLdapParamsForMSActiveDirectory(
			String sSecurityPrincipal, String sSecurityCredentials) {

		Hashtable<String, Object> ldapParams = new Hashtable<String, Object>(12);

		ldapParams.put("java.naming.ldap.version", "3");
		ldapParams.put("java.naming.factory.initial",
				"com.sun.jndi.ldap.LdapCtxFactory");
		if ((servertype == ServerType.MSActiveDirectory)
				&& (searchReturningAttributes.get(ATTR_SID) != null)) {
			ldapParams.put("java.naming.ldap.attributes.binary",
					searchReturningAttributes.get(ATTR_SID));
		}
		ldapParams.put("java.naming.referral", "follow");
		ldapParams.put("java.naming.provider.url", getConnectionUrl());
		if (usessl)
			ldapParams.put(Context.SECURITY_PROTOCOL, "ssl");

		switch (sat) {
		case None:
			ldapParams.put(Context.SECURITY_AUTHENTICATION, "none");

			break;

		case Simple:
			ldapParams.put(Context.SECURITY_AUTHENTICATION, "simple");
			ldapParams.put(Context.SECURITY_PRINCIPAL, sSecurityPrincipal);
			ldapParams.put(Context.SECURITY_CREDENTIALS, sSecurityCredentials);

			break;

		case DIGEST_MD5:
			ldapParams.put(Context.SECURITY_AUTHENTICATION, "DIGEST-MD5");
			ldapParams.put(Context.SECURITY_PRINCIPAL, sSecurityPrincipal);
			ldapParams.put(Context.SECURITY_CREDENTIALS, sSecurityCredentials);

			ldapParams.put("javax.security.sasl.qop", "auth-conf");
			ldapParams.put("javax.security.sasl.strength", "high");
			break;

		case GSSAPI:
			break;
		default:
			break;

		}

		return ldapParams;
	}

	@Override
	void connect(String sSecurityPrincipal, String sSecurityCredentials,
			String ip, ProviderContextHolder ldapLink, PrintWriter pw)
			throws EAuthServerLogic {

		// Сначала мы пытаемся зайти без префикса
		sSecurityPrincipal = getConnectName(sSecurityPrincipal);

		try {
			internalConnect(sSecurityPrincipal, sSecurityCredentials, ldapLink);
		} catch (Exception e) {

			try {
				// Если зайти без префикса не получилось, и у нас есть префикс,
				// то мы можем попробовать войти с префиксом.
				if ((domainName != null) && (!domainName.isEmpty()))
					sSecurityPrincipal = getDomainName() + "\\"
							+ sSecurityPrincipal;
				else {
					// Если префикса нет, то не пытаемся больше войти.
					throw e;
				}
				internalConnect(sSecurityPrincipal, sSecurityCredentials,
						ldapLink);
			} catch (Exception e1) {
				if (getLogger() != null) {
					getLogger().error(
							"Логин пользователя '" + sSecurityPrincipal
									+ "' в '" + getConnectionUrl()
									+ "' не успешен: " + e.getMessage());
				}
				throw EAuthServerLogic.create(e);
			}
		}

	}

	private void internalConnect(String sSecurityPrincipal,
			String sSecurityCredentials, ProviderContextHolder ldapLink)
			throws LoginException, NamingException {
		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger()
					.debug("sSecurityPrincipal='" + sSecurityPrincipal + "'");
			getLogger().debug("sat='" + sat.toString() + "'");
		}

		if (sat == SecurityAuthenticationType.GSSAPI) {
			LoginContext lc = new LoginContext(AuthManager.class.getName(),
					new KerberosCallbackHandler(sSecurityPrincipal,
							sSecurityCredentials));

			lc.login();

			Subject.doAs(lc.getSubject(), new InitialKerberosContext(
					(LDAPLink) ldapLink));
		} else {
			((LDAPLink) ldapLink).ctx = new InitialLdapContext(
					createLdapParamsForMSActiveDirectory(sSecurityPrincipal,
							sSecurityCredentials), null);
		}

		if (getLogger() != null) {
			getLogger().debug(
					"Логин пользователя '" + sSecurityPrincipal + "' в '"
							+ getConnectionUrl() + "' успешен!");
		}
	}

	@Override
	void getUserInfoByName(ProviderContextHolder ldapLink, String name,
			PrintWriter pw) throws EAuthServerLogic {

		NamingEnumeration<SearchResult> searchResults;
		Attributes ldapAttrs;

		String searchName = getSearchName(name);
		String searchFilter = String.format(searchFilterForUser, searchName);

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("searchName='" + name + "'");
			getLogger().debug("searchFilter='" + searchFilter + "'");
		}

		SearchControls ldapSearchCtrls = new SearchControls();
		ldapSearchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		ldapSearchCtrls.setReturningAttributes(searchReturningAttributes
				.values().toArray(new String[0]));

		try {
			for (String sSearchBase : searchBases) {

				if (getLogger() != null) {
					getLogger().debug("sSearchBase='" + sSearchBase + "'");
				}

				searchResults = ((LDAPLink) ldapLink).ctx.search(sSearchBase,
						searchFilter, ldapSearchCtrls);
				if (searchResults.hasMoreElements()) {

					if (getLogger() != null) {
						getLogger().debug(
								"Пользователь '" + searchName
										+ "' найден в sSearchBase='"
										+ sSearchBase + "'");
					}

					ldapAttrs = (searchResults.next()).getAttributes();
					XMLStreamWriter xw = XMLOutputFactory.newInstance()
							.createXMLStreamWriter(pw);
					xw.writeStartDocument("utf-8", "1.0");
					writeUserInfo(xw, ldapAttrs);
					xw.writeEndDocument();
					xw.flush();
					break;
				}
			}
		} catch (Exception e) {
			throw EAuthServerLogic.create(e);
		}
	}

	@Override
	void changePwd(ProviderContextHolder ldapLink, String userName,
			String newpwd) throws EAuthServerLogic {

		String distinguishedName = null;

		try {
			switch (servertype) {
			case MSActiveDirectory:
				NamingEnumeration<SearchResult> searchResults;
				Attributes ldapAttrs;

				final String[] attrsSearch = { "distinguishedName" };

				String searchName = getSearchName(userName);

				String searchFilter = String.format(searchFilterForUser,
						searchName);

				SearchControls ldapSearchCtrls = new SearchControls();
				ldapSearchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
				ldapSearchCtrls.setReturningAttributes(attrsSearch);

				for (String sSearchBase : searchBases) {
					searchResults = ((LDAPLink) ldapLink).ctx.search(
							sSearchBase, searchFilter, ldapSearchCtrls);
					if (searchResults.hasMoreElements()) {
						ldapAttrs = (searchResults.next()).getAttributes();
						distinguishedName = (String) ldapAttrs.get(
								"distinguishedName").get();
						break;
					}
				}

				break;
			case ApacheDS:
				distinguishedName = getConnectName(userName);
				break;
			}

			if (distinguishedName == null)
				throw EAuthServerLogic.create(String.format(USER_NOT_FOUND,
						userName));

			// ------------------------------------------

			ModificationItem[] mods = new ModificationItem[1];

			switch (servertype) {
			case MSActiveDirectory:
				String quotedPassword = "\"" + newpwd + "\"";
				char unicodePwd[] = quotedPassword.toCharArray();
				byte pwdArray[] = new byte[unicodePwd.length * 2];
				for (int i = 0; i < unicodePwd.length; i++) {
					pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
					pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
				}

				mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
						new BasicAttribute("UnicodePwd", pwdArray));

				break;
			case ApacheDS:
				mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
						new BasicAttribute("userPassword", newpwd));

				break;
			}

			((LDAPLink) ldapLink).ctx.modifyAttributes(distinguishedName, mods);
		} catch (NamingException e) {
			throw EAuthServerLogic.create(e);
		}

	}

	@Override
	void importUsers(ProviderContextHolder ldapLink, PrintWriter pw)
			throws EAuthServerLogic {

		NamingEnumeration<SearchResult> searchResults;
		Attributes ldapAttrs;

		String searchFilter = searchFilterForImport;

		if (getLogger() != null) {
			getLogger().debug("Url='" + getConnectionUrl() + "'");
			getLogger().debug("searchFilter='" + searchFilter + "'");
		}

		SearchControls ldapSearchCtrls = new SearchControls();
		ldapSearchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		ldapSearchCtrls.setReturningAttributes(searchReturningAttributes
				.values().toArray(new String[0]));

		try {
			XMLStreamWriter xw = XMLOutputFactory.newInstance()
					.createXMLStreamWriter(pw);
			xw.writeStartDocument("utf-8", "1.0");
			xw.writeStartElement("root");

			for (String sSearchBase : searchBases) {

				if (getLogger() != null) {
					getLogger().debug("sSearchBase='" + sSearchBase + "'");
				}

				searchResults = ((LDAPLink) ldapLink).ctx.search(sSearchBase,
						searchFilter, ldapSearchCtrls);
				while (searchResults.hasMoreElements()) {
					ldapAttrs = (searchResults.next()).getAttributes();

					writeUserInfo(xw, ldapAttrs);
				}
			}
			xw.writeEndDocument();
			xw.flush();
		} catch (Exception e) {
			throw EAuthServerLogic.create(e);
		}
	}

	private static Object safelyGetAttr(Attributes ldapAttrs, String name)
			throws NamingException {
		Attribute a = ldapAttrs.get(name);
		return a == null ? null : a.get();
	}

	private void writeUserInfo(XMLStreamWriter xw, Attributes ldapAttrs)
			throws XMLStreamException, NamingException {

		xw.writeEmptyElement("user");

		String attrLDAP;
		for (String attr : searchReturningAttributes.keySet()) {
			Object objAttr = safelyGetAttr(ldapAttrs,
					searchReturningAttributes.get(attr));
			if (objAttr == null) {
				attrLDAP = ATTR_NOT_DEFINED;
			} else {
				if ((servertype == ServerType.MSActiveDirectory)
						&& (attr.equals(ATTR_SID))) {
					attrLDAP = convertSIDToString((byte[]) objAttr);
				} else {
					attrLDAP = (String) objAttr;
				}
			}

			writeXMLAttr(xw, attr, attrLDAP);
		}
		writeXMLAttr(xw, "domain", domainName);

	}

	@Override
	ProviderContextHolder newContextHolder() {

		return new LDAPLink();
	}

	/**
	 * Соединение с LDAP-сервером.
	 */
	private static class LDAPLink extends ProviderContextHolder {
		private InitialLdapContext ctx;

		@Override
		void closeContext() {
			try {
				if (ctx != null)
					ctx.close();
			} catch (NamingException e) {
				// Не беда, всё равно этот объект уже на выброс...
				e.printStackTrace();
			}
		}

	}

	/**
	 * Устанавливает/Получает имя домена, связанное с данным LDAP-сервером.
	 * Опциональный параметр.
	 * 
	 * @param value
	 */
	public void setDomainName(String value) {
		domainName = value;
	}

	public String getDomainName() {
		return domainName;
	}
}
