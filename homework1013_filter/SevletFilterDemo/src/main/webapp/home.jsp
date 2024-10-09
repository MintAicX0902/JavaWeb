<%--
  Created by IntelliJ IDEA.
  User: ThinkPad
  Date: 2024-10-08
  Time: 10:49
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <title>主页</title>
</head>
<body>
    <h1>欢迎，<%= session.getAttribute("user") %></h1>
    <a href="logout">点这里退出登录</a>
</body>
</html>