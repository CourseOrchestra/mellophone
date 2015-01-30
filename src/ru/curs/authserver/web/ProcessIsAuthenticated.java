package ru.curs.authserver.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /isauthenticated?sesid=...
 */
public class ProcessIsAuthenticated extends BaseProcessorServlet {
	private static final long serialVersionUID = -6071358374749875674L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String sesid = request.getParameter("sesid");

		String ip = getRequestParam(request, "ip");
		if ((ip != null) && ip.isEmpty()) {
			ip = null;
		}

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			try {
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().isAuthenticated(sesid, ip, pw);
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
