package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /loginesiauser?sesid=...
 */
public class ProcessLoginESIAUser extends BaseProcessorServlet {
	private static final long serialVersionUID = -7262116445954365667L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String sesid = request.getParameter("sesid");
		String login = getRequestParam(request, "login");
		String userinfo = getRequestParam(request, "userinfo");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			try {
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().loginESIAUser(sesid, login, userinfo, pw);
				pw.flush();
				
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
