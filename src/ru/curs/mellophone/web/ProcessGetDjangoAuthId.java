package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /getdjangoauthid?sesid=...
 */
public class ProcessGetDjangoAuthId extends BaseProcessorServlet {
	private static final long serialVersionUID = 6468202419982830852L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String djangosesid = request.getParameter("sesid");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");

		try {
			try {
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().getDjangoAuthId(djangosesid, pw);
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
