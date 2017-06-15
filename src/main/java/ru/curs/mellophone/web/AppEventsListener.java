package ru.curs.mellophone.web;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.SQLLoginProvider;

/**
 * Перехватчик старта и остановки приложения.
 */
public class AppEventsListener implements ServletContextListener {

	@Override
	public final void contextInitialized(final ServletContextEvent arg0) {
		AuthManager.getTheManager().productionModeInitialize(arg0.getServletContext());
	}

	@Override
	public final void contextDestroyed(final ServletContextEvent arg0) {
		AuthManager.getTheManager().productionModeDestroy(arg0.getServletContext());
		SQLLoginProvider.unregisterDrivers();
	}

}