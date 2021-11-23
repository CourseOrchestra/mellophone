package ru.curs.mellophone.web;

import ru.curs.mellophone.logic.AuthManager;
import ru.curs.mellophone.logic.EAuthServerLogic;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

public class ProcessUserCreate extends BaseProcessorServlet {
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
                AuthManager.getTheManager().userCreate(token, user);
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
