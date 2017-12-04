package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /getuserlist?login=...&pwd=...
 */
public class ProcessGetUserList extends BaseProcessorServlet {
	private static final long serialVersionUID = 4394356614469305852L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		try {
			try {
				String login = getRequestParam(request, "login");
				String pwd = getRequestParam(request, "pwd");
				String pid = getRequestParam(request, "pid");				
				
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
				
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().getUserList(pid, gp, login, pwd, ip, pw);
				response.setStatus(HttpServletResponse.SC_OK);
				pw.flush();
			} catch (EAuthServerLogic e) {
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}
}
