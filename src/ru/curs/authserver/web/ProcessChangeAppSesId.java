package ru.curs.authserver.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /changeappsesid?oldsesid=...&newsesid=...
 */
public class ProcessChangeAppSesId extends BaseProcessorServlet {

	private static final long serialVersionUID = -9042173526041088151L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String oldId = request.getParameter("oldsesid");
		String newId = request.getParameter("newsesid");

		response.reset();
		setHeaderNoCache(response);
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			AuthManager.getTheManager().changeAppSessionId(oldId, newId);
			response.setStatus(HttpServletResponse.SC_OK);
		} catch (EAuthServerLogic e) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		}

	}
}
