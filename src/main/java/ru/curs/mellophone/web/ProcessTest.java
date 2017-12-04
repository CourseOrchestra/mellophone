package ru.curs.mellophone.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

/**
 * Отладочный сервлет.
 */
public class ProcessTest extends BaseProcessorServlet {
	private static final long serialVersionUID = 3190561898164950825L;

	@Override
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.reset();
		setHeaderNoCache(response);

		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");

		try {
			String s = "E:\\Downloads\\test.txt";
			final PrintWriter pw = new PrintWriter(s);

			class TestThread2 extends Thread {

				private final int index;

				TestThread2(int index1) {

					index = index1;

					setName("тред" + String.valueOf(index + 1));

				}

				@Override
				public void run() {

					try {

						AuthManager.getTheManager().login(
								String.valueOf(index),
								AuthManager.GROUP_PROVIDERS_ALL, "Петров1",
								"пасс2", null);

						// AuthManager.getTheManager().isAuthenticated(
						// String.valueOf(index), null, pw);
						//
						// AuthManager.getTheManager().logout(
						// String.valueOf(index));
						//
						// AuthManager.getTheManager().isAuthenticated(
						// String.valueOf(index), null, pw);

					} catch (EAuthServerLogic e) {
						e.printStackTrace();
					}

					System.out.println("TestThread2 finished:" + getName());

				}
			}

			AuthManager.getTheManager().login(
					String.valueOf("357deea02b6263912cc33e28c56e9382"),
					AuthManager.GROUP_PROVIDERS_ALL, "Петров1", "пасс2", null);

			TestThread2[] tt2 = new TestThread2[5000];
			for (int i = 0; i < tt2.length; i++) {
				tt2[i] = new TestThread2(i);
				tt2[i].start();
			}

			response.setStatus(HttpServletResponse.SC_OK);
			pw.flush();
		} catch (EAuthServerLogic e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			response.flushBuffer();
		}
	}
}
