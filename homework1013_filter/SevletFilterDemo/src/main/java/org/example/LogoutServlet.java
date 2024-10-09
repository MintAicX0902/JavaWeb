package org.example;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebServlet("/logout") // 处理请求路径为/logout的Servlet
public class LogoutServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 获取当前会话（如果当前请求没有会话，则返回 null）
        // 使用false来防止创建不必要的新的对话
        HttpSession session = req.getSession(false);
        if (session != null) {
            // 如果会话存在，就结束用户的登录状态
            session.invalidate();
        }
        // 重定向到登录页面
        resp.sendRedirect(req.getContextPath() + "/login.jsp");
    }
}

