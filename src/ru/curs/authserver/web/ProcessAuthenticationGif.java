package ru.curs.authserver.web;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;

import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.AuthManager;
import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Servlet implementation /authentication.gif?sesid=...
 */
public class ProcessAuthenticationGif extends BaseProcessorServlet {
	private static final long serialVersionUID = 6596513366800084759L;

	private static final String DIR_IMAGES = "images/";
	private static final String COLOR_BANNER = "color.gif";
	private static final String BW_BANNER = "bw.gif";

	private static final String IMAGE_EXT = COLOR_BANNER.substring(COLOR_BANNER
			.lastIndexOf(".") + 1);

	private enum BannerType {
		btColor, btBW
	}

	private void setBanner(HttpServletResponse response, BannerType bt)
			throws IOException {

		String banner = BW_BANNER;
		switch (bt) {
		case btColor:
			banner = COLOR_BANNER;
			break;
		case btBW:
			banner = BW_BANNER;
			break;
		}

		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();

		BufferedImage buffer = ImageIO.read(classLoader
				.getResourceAsStream(DIR_IMAGES + banner));

		OutputStream os = response.getOutputStream();
		ImageIO.write(buffer, IMAGE_EXT, os);
		os.flush();

	}

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		try {
			try {

				Cookie cookAuthsesid = null;

				String sesid = request.getParameter("sesid");
				String authsesid = null;

				Cookie[] cookies = request.getCookies();
				if (cookies != null) {
					for (int i = 0; i < cookies.length; i++) {
						if ("authsesid".equals(cookies[i].getName())) {
							cookAuthsesid = cookies[i];
							break;
						}
					}
				}
				if (cookAuthsesid != null)
					authsesid = cookAuthsesid.getValue();

				authsesid = AuthManager.getTheManager().authenticationGif(
						sesid, authsesid);

				// if ("AUTH_OK".equals(authsesid)) //DEBUG!!!!!!!!!!
				// authsesid = "ww1";

				response.reset();
				setHeaderNoCache(response);

				response.setContentType("image/" + IMAGE_EXT);
				response.setCharacterEncoding("UTF-8");

				response.setStatus(HttpServletResponse.SC_OK);

				if (authsesid == null) {
					if (cookAuthsesid != null) {
						cookAuthsesid.setMaxAge(0);
						cookAuthsesid.setValue("");
						response.addCookie(cookAuthsesid);
					}

					setBanner(response, BannerType.btBW);

				} else {
					if ("AUTH_OK".equals(authsesid)) {

						setBanner(response, BannerType.btColor);

					} else {

						Cookie cookie = new Cookie("authsesid", authsesid);
						response.addCookie(cookie);

						setBanner(response, BannerType.btColor);

					}
				}

			} catch (EAuthServerLogic e) {
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				response.getWriter().append(e.getMessage()).flush();
			}
		} finally {
			response.flushBuffer();
		}
	}
}
