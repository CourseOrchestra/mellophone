package ru.curs.mellophone.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Servlet implementation /setsettings?token=...&lockouttime=...
 */
public class ProcessSetSettings extends BaseProcessorServlet {
	private static final long serialVersionUID = 4394356614469305852L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		try {
			try {
				String token = getRequestParam(request, "token");
				String lockoutTime = getRequestParam(request, "lockouttime");
				String loginAttemptsAllowed = getRequestParam(request, "loginattemptsallowed");
				
				AuthManager.getTheManager().setSettings(token, lockoutTime, loginAttemptsAllowed);
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
