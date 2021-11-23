package ru.curs.mellophone.web;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

public class ProcessUserUpdateDelete extends BaseProcessorServlet {

    private String getSid(HttpServletRequest request) {
        String url = request.getRequestURI();
        return url.substring(url.lastIndexOf("/") + 1);
    }

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response) throws ServletException, IOException {

        response.reset();
        setHeaderNoCache(response);

        response.setContentType("application/xml");
        response.setCharacterEncoding("UTF-8");

        try {
            try {
                String token = getRequestParam(request, "token");
                InputStream user = request.getInputStream();
                AuthManager.getTheManager().userUpdate(token, getSid(request), user);
                response.setStatus(HttpServletResponse.SC_OK);
            } catch (EAuthServerLogic e) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().append(e.getMessage()).flush();
            }
        } finally {
            response.flushBuffer();
        }

    }

    @Override
    protected void doDelete(HttpServletRequest request,
                            HttpServletResponse response) throws ServletException, IOException {

        response.reset();
        setHeaderNoCache(response);

        response.setContentType("application/xml");
        response.setCharacterEncoding("UTF-8");

        try {
            try {
                String token = getRequestParam(request, "token");
                InputStream user = request.getInputStream();
                AuthManager.getTheManager().userDelete(token, getSid(request));
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
