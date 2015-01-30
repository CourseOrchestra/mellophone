package ru.curs.authserver.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /login?sesid=...&login=...&pwd=...
 */
public class ProcessLogin2 extends BaseProcessorServlet {
	private static final long serialVersionUID = -8581655214735635867L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			try {

				String sesid = request.getParameter("sesid");
				String login = getRequestParam(request, "login");
				String pwd = getRequestParam(request, "pwd");

				String authsesid = AuthManager.getTheManager().login(sesid,
						AuthManager.GROUP_PROVIDERS_ALL, login, pwd, null);

				response.setStatus(HttpServletResponse.SC_OK);

				response.addCookie(new Cookie("authsesid", authsesid));

			} catch (EAuthServerLogic e) {
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}
}
