package ru.curs.authserver.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /changepwd?sesid=...&oldpwd=...&newpwd=...
 */
public class ProcessChangePwd extends BaseProcessorServlet {
	private static final long serialVersionUID = -4038953111570852670L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String sesid = request.getParameter("sesid");
		String oldpwd = getRequestParam(request, "oldpwd");
		String newpwd = getRequestParam(request, "newpwd");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		try {
			try {
				String name = AuthManager.getTheManager().changeOwnPwd(sesid,
						oldpwd, newpwd);
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().append(name).flush();
			} catch (EAuthServerLogic e) {
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}

}
