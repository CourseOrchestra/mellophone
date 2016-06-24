package ru.curs.mellophone.web;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;

/**
 * Фильтр преобработки.
 * 
 */
public class PreProcessFilter implements Filter {

	private static final String WELCOME_PAGE = "welcome.jsp";
	private static final String CACHE_CONTROL = "Cache-Control";

	@Override
	public void doFilter(final ServletRequest request,
			final ServletResponse response, final FilterChain chain)
			throws IOException, ServletException {
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;


				if (AuthManager.getTheManager().getInitializationError() != null) {
					httpResponse.reset();

					httpResponse.setHeader("Pragma", "no-cache");
					httpResponse.setHeader(CACHE_CONTROL, "must-revalidate");
					httpResponse.setHeader(CACHE_CONTROL, "no-cache");
					httpResponse.setHeader(CACHE_CONTROL, "no-store");
					httpResponse.setDateHeader("Expires", 0);

					httpResponse.setContentType("text/html");
					httpResponse.setCharacterEncoding("UTF-8");

					httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
					httpResponse
							.getWriter()
							.append(AuthManager.getTheManager()
									.getInitializationError()).flush();

					return;
				}

		}

		chain.doFilter(request, response);

	}

	@Override
	public void init(final FilterConfig config) throws ServletException {
	}

	@Override
	public void destroy() {
	}

}
