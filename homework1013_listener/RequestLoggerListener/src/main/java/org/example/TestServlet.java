// 测试 Servlet 实现
package org.example;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@WebServlet("/test")
public class TestServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        long startTime = System.currentTimeMillis();
        resp.setContentType("text/html;charset=UTF-8");

        // 获取请求信息
        String clientIP = (String) req.getAttribute("clientIP");
        String method = (String) req.getAttribute("method");
        String uri = (String) req.getAttribute("uri");
        String queryString = (String) req.getAttribute("queryString");
        String userAgent = (String) req.getAttribute("userAgent");
        Long duration = (Long) req.getAttribute("duration");
        if (duration == null) {
            duration = 0L; // 设置默认处理时间为 0
        }

        // 使用 resp.getWriter() 获取响应输出流，然后写入 HTML 内容到客户端浏览器
        resp.getWriter().write("<h1>请求日志测试成功</h1>");
        resp.getWriter().write("<p>请求时间: " + new Date() + "</p>");
        resp.getWriter().write("<p>客户端 IP: " + clientIP + "</p>");
        resp.getWriter().write("<p>请求方法: " + method + "</p>");
        resp.getWriter().write("<p>请求 URI: " + uri + "</p>");
        resp.getWriter().write("<p>查询字符串: " + (queryString.isEmpty() ? "无" : queryString) + "</p>");
        resp.getWriter().write("<p>用户代理: " + userAgent + "</p>");
        long endTime = System.currentTimeMillis();
        duration = endTime - startTime;
        req.setAttribute("duration", duration);
        resp.getWriter().write("<p>处理时间: " + duration + " 毫秒</p>");
    }
}