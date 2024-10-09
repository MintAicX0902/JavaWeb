<%--
  Created by IntelliJ IDEA.
  User: ThinkPad
  Date: 2024-10-08
  Time: 10:45
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" %>
<% String loginMsg = request.getParameter("login_msg"); %>
<% if (loginMsg != null) { %>
<p><%= loginMsg %></p>
<% } %>
<!DOCTYPE html>
<html>
<head>
    <title>登录</title>
</head>
<body>
<h1>登录页面</h1>
<form action="doLogin" method="post">
    用户名：<input type="text" name="username"/><br/>
    密码：<input type="password" name="password"/><br/>
    <input type="submit" value="登录"/>
</form>
</body>
</html>