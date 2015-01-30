package ru.curs.mellophone.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /changeuserpwd?sesid=...&username=...&newpwd=...
 */
public class ProcessChangeUserPwd extends BaseProcessorServlet {
	private static final long serialVersionUID = -8330645707562369703L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String sesid = request.getParameter("sesid");
		String username = getRequestParam(request, "username");
		String newpwd = getRequestParam(request, "newpwd");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			try {
				String name = AuthManager.getTheManager().changeUserPwd(sesid,
						username, newpwd);
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
