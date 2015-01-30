package ru.curs.authserver.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /importgroupsproviders.
 */
public class ProcessImportGroupsProviders extends BaseProcessorServlet {
	private static final long serialVersionUID = -9165162410534732369L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		try {
			try {

				response.reset();
				setHeaderNoCache(response);

				response.setContentType("text/html");
				response.setCharacterEncoding("UTF-8");

				PrintWriter pw = response.getWriter();
				if (AuthManager.getTheManager().importGroupsProviders(pw)) {
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
