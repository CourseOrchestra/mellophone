<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="ru.curs.mellophone.logic.AuthManager"%>

<html>
<head>
<title>Mellophone</title>
</head>
<body>
<%
	String mess = "Mellophone запущен";
    if(AuthManager.getTheManager().getInitializationError() != null){
    	mess = AuthManager.getTheManager().getInitializationError();
    }
%>
<div id="welc"><%=mess%></div>
</body>
</html>