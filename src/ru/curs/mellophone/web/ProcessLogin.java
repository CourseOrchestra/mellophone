package ru.curs.mellophone.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /login?sesid=...&login=...&pwd=...
 */
public class ProcessLogin extends BaseProcessorServlet {
	private static final long serialVersionUID = -2281774842043979233L;

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

				String gp = getRequestParam(request, "gp");
				if (gp == null) {
					gp = AuthManager.GROUP_PROVIDERS_ALL;
				}
				if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
					gp = "";
				}

				String ip = getRequestParam(request, "ip");
				if ((ip != null) && ip.isEmpty()) {
					ip = null;
				}

				AuthManager.getTheManager().login(sesid, gp, login, pwd, ip);

				response.setStatus(HttpServletResponse.SC_OK);
			} catch (EAuthServerLogic e) {
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}
}
