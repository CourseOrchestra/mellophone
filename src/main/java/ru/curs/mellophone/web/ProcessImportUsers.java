package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;

/**
 * Servlet implementation /importusers?sesid=...
 */
public class ProcessImportUsers extends BaseProcessorServlet {
	private static final long serialVersionUID = -6173264480481900113L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

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
		} finally {
			response.flushBuffer();
		}
	}
}
