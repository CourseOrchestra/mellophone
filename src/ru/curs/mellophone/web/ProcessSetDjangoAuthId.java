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
 * Servlet implementation
 * /setdjangoauthid?sesid=...&djangoauthid=...&login=...&sid=...
 */
public class ProcessSetDjangoAuthId extends BaseProcessorServlet {
	private static final long serialVersionUID = -1782888813012667269L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			try {

				String djangosesid = request.getParameter("sesid");
				String djangoauthid = getRequestParam(request, "djangoauthid");
				String login = getRequestParam(request, "login");
				String sid = getRequestParam(request, "sid");
				String djangoCallback = request.getParameter("callback");

				String authid = AuthManager.getTheManager().setDjangoAuthId(
						djangosesid, djangoauthid, login, sid);

				Cookie cookie = new Cookie("authsesid", authid);
				response.addCookie(cookie);

				PrintWriter pw = response.getWriter();
				pw.append(djangoCallback + "();");
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
