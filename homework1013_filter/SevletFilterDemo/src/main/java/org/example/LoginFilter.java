package org.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.List;

@WebFilter("/*") // 应用于所有请求
public class LoginFilter implements Filter {

    // 排除列表，下面是不需要过滤的路径
    private static final List<String> EXCLUDE_URL_LIST = Arrays.asList(
            "/login",
            "/doLogin",
            "/logout",
            // 静态资源
            "/public",
            "/css/",
            "/js/",
            "/images/"
    );

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // 初始化
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 将请求和响应对象转换为HttpServletRequest和HttpServletResponse，以便访问更多与HTTP相关的方法。
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // 获取用户请求的 URI（如/home.jsp）
        String requestURI = httpRequest.getRequestURI();

        // 检查请求路径是否在排除列表中（不需要登录就可以访问的路径）
        if (isExcluded(requestURI, httpRequest.getContextPath())) {
            // 如果请求在排除列表中，则直接放行，不进行登录验证
            chain.doFilter(request, response);
            return; // 返回，避免后续代码被执行
        }

        // 获取当前会话（如果没有会话则返回 null，避免不必要的会话创建）
        HttpSession session = httpRequest.getSession(false);
        if (session != null && session.getAttribute("user") != null) {
            // 如果会话存在且用户信息（"user"）存在，说明用户已登录，放行请求
            chain.doFilter(request, response);
        } else {
            // 如果用户未登录，重定向到登录页面
            httpResponse.sendRedirect(httpRequest.getContextPath() + "/login.jsp");
        }
        return; // 确保不再执行后续代码，解决可能出现的 "too_many_redirects" 问题
    }

    @Override
    public void destroy() {
        // 资源释放
    }

    // requestURI：请求的 URI
    private boolean isExcluded(String requestURI, String contextPath) {
        for (String exclude : EXCLUDE_URL_LIST) {
            // 如果请求路径等于上下文路径加排除路径，或者请求路径以上下文路径加排除路径开头
            if (requestURI.equals(contextPath + exclude) || requestURI.startsWith(contextPath + exclude)) {
                return true; // 在排除列表中，返回 true
            }
        }
        return false; // 不在排除列表中，返回 false
    }
}