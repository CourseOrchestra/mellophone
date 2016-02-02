package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
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
		String djangoCallback = request.getParameter("callback");

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		// -----------------------------------------------

		String authsesid = null;
		Cookie cookAuthsesid = null;

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				if ("authsesid".equals(cookies[i].getName())) {
					cookAuthsesid = cookies[i];
					break;
				}
			}
		}
		if (cookAuthsesid != null) {
			authsesid = cookAuthsesid.getValue();
		}
		// -----------------------------------------------

		try {
			try {
				PrintWriter pw = response.getWriter();
				AuthManager.getTheManager().getDjangoAuthId(djangosesid,
						authsesid, djangoCallback, pw);
				pw.flush();
				response.setStatus(HttpServletResponse.SC_OK);
			} catch (EAuthServerLogic e) {

				PrintWriter pw = response.getWriter();
				pw.append(djangoCallback + "();");
				pw.flush();

				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				// response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}
}
