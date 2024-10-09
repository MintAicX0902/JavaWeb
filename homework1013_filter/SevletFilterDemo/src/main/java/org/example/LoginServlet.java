package org.example;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebServlet("/doLogin")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 获取输入的用户名和密码
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        // 这里设置用户名为admin，密码为123456
        if ("admin".equals(username) && "123456".equals(password)) {
            // 登录成功，设置 session
            // 用于获取与当前请求关联的会话对象
            HttpSession session = req.getSession();
            // 将用户名存入会话中，表示用户已成功登录
            // 存入会话的 "user" 属性可以在用户与服务器的整个会话过程中被访问，这样无需每次请求都重新验证用户
            session.setAttribute("user", username);
            // 重定向到主页
            resp.sendRedirect(req.getContextPath() + "/home.jsp");
        } else {
            // 登录失败，跳转到登录失败界面
            // 使用 req.setAttribute() 方法向请求对象添加属性 "errorMsg"，其值为 "用户名或密码错误"
            // 这个属性可以在请求转发到的页面中（fail.jsp）通过 request.getAttribute("errorMsg") 获取到，用于在页面上显示错误提示
            req.setAttribute("errorMsg", "用户名或密码错误");
            // 将请求转发到fail.jsp
            // 获取请求转发器，将请求转发到 fail.jsp 页面，调用 forward(req, resp) 方法将请求和响应对象转发到目标页面
            req.getRequestDispatcher("/fail.jsp").forward(req, resp);
        }
    }
}
