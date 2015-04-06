<%@ page language="java" contentType="text/html; charset=UTF-8"
pageEncoding="UTF-8"%>


<html>
<head>
<title>Авторизация</title>
<script type="text/javascript">

function getXMLObject(){
	  var obj;
	  try {
		  obj = new ActiveXObject("Msxml2.XMLHTTP");
	  } catch (e) {
	    try {
	    	obj = new ActiveXObject("Microsoft.XMLHTTP");
	    } catch (E) {
	    	obj = false;
	    }
	  }
	  if (!obj && typeof XMLHttpRequest!="undefined") {
		  obj = new XMLHttpRequest();
	  }
	  return obj;
}
 
var xmlhttp = new getXMLObject();
 
function checkLogin() {
  if(xmlhttp) {
    var params = "sesid=<%=request.getParameter("sesid")%>" 
    + "&login=" + encodeURIComponent(document.getElementsByName("j_username")[0].value)
    + "&pwd=" + encodeURIComponent(document.getElementsByName("j_password")[0].value);
    
    xmlhttp.open("POST", "login2", true);
    xmlhttp.onreadystatechange  = handleServerResponse;    
    xmlhttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xmlhttp.send(params);
  }
  else
  {
    alert("Ошибка при создании объекта XMLHttpRequest. Выполнение операции невозможно.");  
  }
}

function handleServerResponse() {
   if (xmlhttp.readyState == 4) {
     if(xmlhttp.status == 200) {
   	   doRedirect();
     }
     else {
       if(xmlhttp.status == 403) {
           alert("Логин или пароль пользователя введены неверно.");
       }
       else {
           alert("Ошибка сервера: "+xmlhttp.status+" ("+xmlhttp.statusText+")");
       }
     }
   }
}

function doRedirect() {
    window.location.href = "<%=request.getParameter("redirect")%>/?sesid=<%=request.getParameter("sesid")%>";
}
	
function checkAuthenticationImageSize() {
	var pic = document.getElementById("authenticationImage");
	var w = pic.offsetWidth;  
	
	if (w == 178) {
		doRedirect();
	}
	else {
	    document.loginForm.style.display = "";
	}
}
	
</script>
</head>

<body onLoad="checkAuthenticationImageSize()">
<form id="loginForm" name="loginForm" style="display:none" onsubmit="checkLogin(); return false;">
<!--  onsubmit="... return false;". Здесь "return false;" -- НУЖНО!!   -->
<span id="helloMessage" style="font-size: 27px;color:green">Авторизация</span>
<table>
  <tr>
    <td align="right">Имя пользователя</td>
    <td><input id="j_username" type="text" name="j_username" /></td>
  </tr>
  <tr>
    <td align="right">Пароль</td>
    <td><input  id="j_password" type="password" name="j_password" /></td>
  </tr>
  <tr>
    <td colspan="2" align="right">
      <input type="submit" value="Войти" />
    </td>
  </tr>
</table>
</form>

<img src="authentication.gif?sesid=<%=request.getParameter("sesid")%>" alt=" " id="authenticationImage" style="visibility:hidden" />

</body>
</html>