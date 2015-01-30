package ru.curs.authserver.web;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.UUID;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.authserver.logic.EAuthServerLogic;

/**
 * Базовый класс сервлетов приложения.
 * 
 */
public class BaseProcessorServlet extends HttpServlet {

	private static final String CACHE_CONTROL = "Cache-Control";
	private static final long serialVersionUID = -6279583835651409511L;

	/**
	 * Извлекает из запроса параметр с перекодировкой в "UTF-8".
	 * 
	 * @param req
	 *            Запрос
	 * @param name
	 *            Имя параметра
	 * 
	 * @return Значение параметра
	 * 
	 * @throws UnsupportedEncodingException
	 *             В случае ошибки перекодирования
	 */
	protected static final String getRequestParam(HttpServletRequest req,
			String name) throws UnsupportedEncodingException {

		String value = req.getParameter(name);

		if (value != null) {
			value = decodeParam(value);
		}

		return value;

	}

	private static String decodeParam(final String param)
			throws UnsupportedEncodingException {
		String s = param;

		s = new String(s.getBytes("ISO8859_1"), "UTF-8");
		s = URLDecoder.decode(s, "UTF-8");

		s = s.replace("AB4AFD63A4C", "%");
		s = s.replace("D195B4C989F", "+");

		return s;
	}

	/**
	 * Извлекает из запроса параметр с типом UUID, применяя все необходимые
	 * предосторожности.
	 * 
	 * @param req
	 *            Запрос
	 * @param name
	 *            Имя параметра
	 * @return UUID если параметр удалось извлечь и распарсить.
	 * @throws EAuthServerLogic
	 *             если параметр не удалось извлечь и распарсить.
	 */
	protected static final UUID getUUIDParam(HttpServletRequest req, String name)
			throws EAuthServerLogic {
		try {
			return UUID.fromString(req.getParameter(name));
		} catch (Exception e) {
			throw EAuthServerLogic.create("Неверный формат GUID");
		}
	}

	/**
	 * Возвращает содержимое реквеста в виде строки.
	 * 
	 * @param request
	 *            реквест
	 * @throws java.io.IOException
	 *             ошибка чтения
	 */
	protected static String getRequestAsString(HttpServletRequest request)
			throws java.io.IOException {

		BufferedReader requestData = new BufferedReader(new InputStreamReader(
				request.getInputStream(), "UTF-8"));

		StringBuffer stringBuffer = new StringBuffer();
		String line;

		stringBuffer.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");

		// Читаем все строчки
		while ((line = requestData.readLine()) != null) {
			stringBuffer.append(line);
		}

		line = stringBuffer.toString();

		return line;
	}

	/**
	 * Борьба с кешированием.
	 * 
	 * @param response
	 *            HttpServletResponse
	 */
	protected void setHeaderNoCache(HttpServletResponse response) {

		response.setHeader("Pragma", "no-cache");
		response.setHeader(CACHE_CONTROL, "must-revalidate");
		response.setHeader(CACHE_CONTROL, "no-cache");
		response.setHeader(CACHE_CONTROL, "no-store");
		response.setDateHeader("Expires", 0);

	}

}
