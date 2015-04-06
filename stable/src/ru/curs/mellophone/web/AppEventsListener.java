package ru.curs.mellophone.web;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import ru.curs.mellophone.logic.SQLLoginProvider;

/**
 * Перехватчик старта и остановки приложения.
 */
public class AppEventsListener implements ServletContextListener {

	@Override
	public final void contextInitialized(final ServletContextEvent arg0) {
	}

	@Override
	public final void contextDestroyed(final ServletContextEvent arg0) {
		SQLLoginProvider.unregisterDrivers();
	}

}