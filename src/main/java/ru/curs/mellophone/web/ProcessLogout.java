package ru.curs.mellophone.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;

/**
 * Servlet implementation /logout?sesid=...
 */
public class ProcessLogout extends BaseProcessorServlet {
	private static final long serialVersionUID = -1621387961070375593L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		try {
			String sesid = request.getParameter("sesid");

			AuthManager.getTheManager().logout(sesid);
		} finally {
			response.flushBuffer();
		}
	}

}
