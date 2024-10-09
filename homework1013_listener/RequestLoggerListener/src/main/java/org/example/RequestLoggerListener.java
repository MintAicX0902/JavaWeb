package org.example;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.logging.Logger;

@WebListener
public class RequestLoggerListener implements ServletRequestListener {

    private static final Logger logger = Logger.getLogger(RequestLoggerListener.class.getName());
    // Logger.getLogger(RequestLoggerListener.class.getName()) 用于创建或获取一个名为 RequestLoggerListener 的 Logger 实例
    // RequestLoggerListener.class.getName() 作为日志记录器的名称，通常是类的全限定名，这样便于区分不同类的日志来源
    // private：表示该 Logger 对象只能在当前类中使用
    // static：表示 Logger 对象属于类本身，而不是类的某个实例，意味着所有对象实例共享同一个日志记录器
    // final：表示这个 Logger 对象是常量，初始化之后不能改变引用，确保整个类使用同一个日志对象

    @Override
    // 在请求开始时调用
    public void requestInitialized(ServletRequestEvent sre) {
        // 获取当前的 HttpServletRequest 对象
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
        // 将请求开始的时间记录到请求属性中，方便后续计算请求处理时间
        request.setAttribute("startTime", System.currentTimeMillis());
        // 获取客户端 IP 地址
        String clientIP = request.getRemoteAddr();
        // 获取请求的方法（GET, POST 等）
        String method = request.getMethod();
        // 获取请求的 URI
        String uri = request.getRequestURI();
        // 获取查询字符串，如果没有则为空字符串
        String queryString = request.getQueryString() == null ? "" : request.getQueryString();
        // 获取请求头中的 User-Agent 信息
        String userAgent = request.getHeader("User-Agent");

        // 记录请求初始化的详细信息，包括时间、IP、请求方法、URI、查询字符串和 User-Agent
        // info() 方法用于记录一般的操作信息，通常用于标识系统的正常运行状态。
        // String.format() 用于格式化字符串，类似于 C 语言中的 printf()，它允许将变量值插入到特定格式的字符串中。
        logger.info(String.format("请求初始化: 时间=%s, 客户端IP=%s, 请求方法=%s, 请求URI=%s, 查询字符串=%s, 用户代理=%s",
                new Date(), clientIP, method, uri, queryString, userAgent));

        // 将请求的相关信息存入请求属性中，方便在请求结束时打印到浏览器上
        request.setAttribute("clientIP", clientIP);
        request.setAttribute("method", method);
        request.setAttribute("uri", uri);
        request.setAttribute("queryString", queryString);
        request.setAttribute("userAgent", userAgent);
    }

    // 在请求结束时调用
    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        // 获取当前的 HttpServletRequest 对象
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
        // 获取请求开始的时间
        Long startTime = (Long) request.getAttribute("startTime");
        if (startTime != null) {
            // 计算请求的结束时间和处理持续时间
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            // 记录请求结束的详细信息，包括 URI 和处理时间
            logger.info(String.format("请求销毁: URI=%s, 处理时间=%d 毫秒",
                    request.getRequestURI(), duration));

            // 将处理时间存入请求属性，以便后续在浏览器中显示
            request.setAttribute("duration", duration);
        }
    }
}
