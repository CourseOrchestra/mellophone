package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /importusers?sesid=...
 */
public class ProcessImportUsers extends BaseProcessorServlet {
	private static final long serialVersionUID = -6173264480481900113L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		try {
			try {

				String sesid = request.getParameter("sesid");

				response.reset();
				setHeaderNoCache(response);

				response.setContentType("text/html");
				response.setCharacterEncoding("UTF-8");

				PrintWriter pw = response.getWriter();
				if (AuthManager.getTheManager().importUsers(sesid, pw)) {
					response.setStatus(HttpServletResponse.SC_OK);
				} else {
					response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				}
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
