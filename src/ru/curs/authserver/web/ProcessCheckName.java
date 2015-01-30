package ru.curs.authserver.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /checkname?sesid=...&name=...
 */
public class ProcessCheckName extends BaseProcessorServlet {
	private static final long serialVersionUID = 6988185890301798494L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String sesid = request.getParameter("sesid");
		String name = getRequestParam(request, "name");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		try {
			try {
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().checkName(sesid, name, pw);
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
