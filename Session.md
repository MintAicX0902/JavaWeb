<font face="黑体">
  
# 《实验一: 会话技术知识扩展》
>**学院:省级示范性软件学院**
>
>**题目:**《实验一: 会话技术内容扩展》
>
>**姓名:** 李璐辰
>
>**学号:** 2200770244
>
>**班级:** 软工2204
>
>**日期:** 2024-09-22
>
>**实验环境:** IntelliJ IDEA 2024.2.0.1
  
# 一、实验目的

1. 掌握会话安全性的相关知识，包括会话劫持、XSS、CSRF的原理和防御措施。
  
2. 理解分布式环境下的会话管理问题，学习Session集群的解决方案。
  
3. 学习会话状态的序列化和反序列化，了解其在分布式系统中的重要性。

# 二、实验内容

## 1. 会话安全性

### 1.1会话劫持和防御

**原理:** 会话劫持是指攻击者通过窃取用户的会话标识(如Session ID)，冒充用户与服务器进行交互，获取用户的权限和信息。

**防御措施:**

- **使用HTTPS加密传输:** 通过SSL/TLS协议加密数据传输，防止Session ID被窃听。
- **设置HttpOnly和Secure属性:** 防止客户端脚本访问Cookie，减少被XSS攻击窃取的风险。

  ```java
  Cookie cookie = new Cookie("JSESSIONID", session.getId());
  cookie.setHttpOnly(true);
  cookie.setSecure(true);
  response.addCookie(cookie);
  ```
  
- **会话超时控制:** 设置合理的会话超时时间，降低Session ID被长期利用的可能性。

  ```java
  session.setMaxInactiveInterval(30 * 60); // 30分钟
  ```
  
- **定期更换Session ID:** 在关键操作后重新生成Session ID，防止固定会话被利用。
  
  ```java
  String oldSessionId = session.getId();
  session.invalidate();
  HttpSession newSession = request.getSession(true);
  ```
  
### 1.2 跨站脚本攻击(XSS)和防御

**原理:** XSS攻击是指攻击者在网页中注入恶意脚本，当其他用户访问时，恶意脚本被执行，从而窃取用户信息或篡改页面内容。

**实例:** 

```html
<html>
<head>
<meta charset="utf-8">
<meta lang="zh">
    <style>
        .txrow {
            flex-direction: row;
            width:50%;
        }
        #cmtInput {
            width:100%;
            height:100px;
        }
    </style>
    <script>
        function comment() {
            let input = document.getElementById("cmtInput")
            let c = document.getElementById("cmtContent")

            let newDiv = document.createElement("div")
            newDiv.innerHTML = input.value
            c.appendChild(newDiv)
        }
    </script>
</head>
<body>
    <div style="display:flex;">
        <div class="txrow">
            <textarea id="cmtInput"></textarea><button onclick="comment();">评论</button>
        </div>
        <div style="width:10px;"></div>
        <div class="txrow" id="cmtContent"></div>
    </div>
</body>
</html>
```

若未进行转义，用户输入语句如下：

```html
<a href="javascript:alert('你被攻击了！');">9999现金点击就送</a>

<img onerror="alert(123)" src="fsd"/>
```

![](https://github.com/MintAicX0902/JavaWeb/blob/main/images/XssAttackExample.png)

这时，只要点击了a标签，就会执行相应的脚本，弹出“你被攻击了！”。然而，实际中的脚本多数时候会带来更加严重的后果。所以，不要点击网页上的广告，尤其是在已经登陆过的网站，许多个人信息的泄露都是这样来的。

**防御措施:** 
  
- **输入验证和输出编码:** 对用户输入的数据进行严格的验证和过滤，并在输出时进行编码，防止脚本执行。
  
  ```java
  // 使用Apache Commons Text进行HTML编码
  String safeContent = StringEscapeUtils.escapeHtml4(userInput);
  ```
  
- **使用内容安全策略(CSP):** 通过设置HTTP头`Content-Security-Policy`,限制页面可以加载的资源。
  
  ```java
  response.setHeader("Content-Security-Policy", "default-src 'self'");
  ```
  
- **避免直接在页面中拼接用户输入:** 使用模板引擎或框架提供的防御机制，避免手动拼接字符串。
  
### 1.3 跨站请求伪造(CSRF)和防御
  
**原理:** CSRF攻击是指攻击者引诱已登录用户访问攻击者构造的恶意链接，导致用户在不知情的情况下执行了非本意的操作。

**防御措施:**

- **使用CSRF Token:** 在表单或请求中加入随机生成的Token，服务器验证Token的有效性。

  ```java
  // 生成Token并存储在Session中
  String csrfToken = UUID.randomUUID().toString();
  session.setAttribute("csrfToken", csrfToken);
  ```
  
  ```html
  <!-- 在表单中加入隐藏域 -->
  <input type="hidden" name="csrfToken" value="${csrfToken}">
  ```
  
  ```java
  // 在服务器端验证Token
  String sessionToken = (String) session.getAttribute("csrfToken");
  String requestToken = request.getParameter("csrfToken");
  if (sessionToken == null || !sessionToken.equals(requestToken)) {
    throw new SecurityException("CSRF Token验证失败");
  }
  ```
  
- **验证Referer或Origin头:** 检查请求的来源是否为可信域名。

- **使用SameSite属性的Cookie:** 限制Cookie的跨站发送。

  ```java
  Cookie cookie = new Cookie("key", "value");
  cookie.setPath("/");
  cookie.setHttpOnly(true);
  cookie.setSecure(true);
  cookie.setAttribute("SameSite", "Strict");
  response.addCookie(cookie);
  ```
  
## 2. 分布式会话管理
  
### 2.1 分布式环境下的会话同步问题
在分布式系统中，用户的请求可能被路由到不同的服务器，如果会话信息不共享，会导致用户需要在每台服务器上重复登录，造成不良的用户体验。

### 2.2 Session集群解决方案
  
**会话粘性(Session Sticky):**

- 原理：使用负载均衡策略，将同一用户的请求始终分配到同一台服务器。

- 缺点：当服务器宕机时，会话信息丢失；负载不均衡。
  
**会话复制(Session Replication):**

- 原理：在服务器之间复制会话信息，保证所有服务器都持有相同的会话数据。
  
- 缺点：网络开销大，复杂度高。

**集中式会话存储:**

- 原理：使用独立的存储系统(如Redis、Memcached)来保存会话信息，各服务器从中读取和写入会话数据。
  
- 优点：高可用、可扩展、性能好。
  
### 2.3 使用Redis等缓存技术实现分布式会话
  
**步骤:**

**1. 引入依赖:**

  ```xml
  <dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
  </dependency>
  ```

**2. 配置Redis连接:**
  
  ```java
  @Configuration
  public class RedisConfig {
    @Bean
    public LettuceConnectionFactory connectionFactory() {
        return new LettuceConnectionFactory();
    }
  } 
  ```
  
**3. 启用Redis HTTP对话:**
  
  ```java
  @Configuration
  @EnableRedisHttpSession
  public class HttpSessionConfig {
  }
  ```
  
**4. 使用对话:**
  
像使用普通的HttpSession一样使用，数据将自动存储在Redis中。
  
## 3. 会话状态的序列化和反序列化
  
- **会话状态的序列化和反序列化**
  
**原理:** 序列化是将对象转换为字节序列，以便存储或传输；反序列化是将字节序列恢复为对象。会话状态的序列化和反序列化用于在不同服务器或进程之间传递会话信息。

- **为什么需要序列化会话状态**
  
**持久化存储:** 在分布式环境下，需要将会话数据存储在共享的存储介质中。

**网络传输:** 会话数据需要通过网络在服务器之间传输。
  
**3.1 Java对象序列化**
  
实现``Serializable``接口：使对象可序列化。

  ```java
  public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private String password;

    // getters and setters
  }
  ```

**3.2 自定义序列化策略**
  
- 使用``transient``关键字：不需要序列化的字段使用``transient``修饰。

  ```java
  public class User implements Serializable {
    private String username;
    private transient String password; // 不序列化
   }
  ```

- 自定义序列化方法：实现``writeObject``和``readObject``方法。

  ```java
  private void writeObject(ObjectOutputStream oos) throws IOException   {
    oos.defaultWriteObject();
    // 自定义序列化逻辑
  }

  private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();
    // 自定义反序列化逻辑
  }
  ```
  
# 三、问题及解决办法
  
**1. 问题:** 在防御XSS攻击时，手动对每个输入和输出都进行转义，工作量大且容易遗漏。

- **解决办法:** 使用成熟的模板引擎(如Thymeleaf、Freemarker)或框架自带的防御机制，这些工具默认对输出进行HTML编码，减少人为失误。

**2. 问题:** 使用Redis存储会话，可能导致单点故障，影响系统的可用性。

- **解决办法:** 配置Redis集群或主从架构，提高Redis的可用性和容错性；在应用层实现故障转移机制。

**3. 问题:** 序列化对象时，可能存在安全漏洞(如反序列化漏洞)，攻击者可能通过构造恶意对象进行攻击。

- **解决办法:** 在反序列化时，使用白名单机制，限制可反序列化的类；或者采用更安全的序列化方式(如JSON序列化)，避免使用Java默认的序列化机制。

**4. 问题:** CSRF Token的管理增加了开发的复杂度，可能出现Token验证失败的问题。

- **解决办法:** 使用框架自带的CSRF防御机制(如Spring Security)，减少手动处理的复杂度；确保Token的一致性和有效性，注意在负载均衡和分布式环境下的Token共享问题。

**5. 问题:** 在高并发情况下，集中式会话存储可能成为性能瓶颈。

- **解决办法:** 优化Redis等存储的性能，使用读写分离、缓存等策略；或者采用无状态的会话管理(如JWT)，减少对集中式存储的依赖。

# 附录：SpringBoot防范XSS攻击

## 1. 自定义过滤器

```java
/**
 * XSS过滤处理
 * 
 * @author lh
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper
{
    /**
     * @param request
     */
    public XssHttpServletRequestWrapper(HttpServletRequest request)
    {
        super(request);
    }

    // 重写获取参数进行转义
    @Override
    public String[] getParameterValues(String name)
    {
        String[] values = super.getParameterValues(name);
        if (values != null)
        {
            int length = values.length;
            String[] escapesValues = new String[length];
            for (int i = 0; i < length; i++)
            {
                // 防xss攻击和过滤前后空格
                escapesValues[i] = EscapeUtil.clean(values[i]).trim();
            }
            return escapesValues;
        }
        return super.getParameterValues(name);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException
    {
        // 非json类型，直接返回
        if (!isJsonRequest())
        {
            return super.getInputStream();
        }

        // 为空，直接返回
        String json = IOUtils.toString(super.getInputStream(), "utf-8");
        if (StringUtils.isEmpty(json))
        {
            return super.getInputStream();
        }

        // xss过滤
        json = EscapeUtil.clean(json).trim();
        byte[] jsonBytes = json.getBytes("utf-8");
        final ByteArrayInputStream bis = new ByteArrayInputStream(jsonBytes);
        return new ServletInputStream()
        {
            @Override
            public boolean isFinished()
            {
                return true;
            }

            @Override
            public boolean isReady()
            {
                return true;
            }

            @Override
            public int available() throws IOException
            {
                return jsonBytes.length;
            }

            @Override
            public void setReadListener(ReadListener readListener)
            {
            }

            @Override
            public int read() throws IOException
            {
                return bis.read();
            }
        };
    }

    /**
     * 是否是Json请求
     * 
     * @param request
     */
    public boolean isJsonRequest()
    {
        String header = super.getHeader(HttpHeaders.CONTENT_TYPE);
        return StringUtils.startsWithIgnoreCase(header, MediaType.APPLICATION_JSON_VALUE);
    }
}
```

## 2. 需要用到的StringUtils类

```java
/**
     * 查找指定字符串是否匹配指定字符串列表中的任意一个字符串
     * 
     * @param str 指定字符串
     * @param strs 需要检查的字符串数组
     * @return 是否匹配
     */
    public static boolean matches(String str, List<String> strs)
    {
        if (isEmpty(str) || isEmpty(strs))
        {
            return false;
        }
        for (String pattern : strs)
        {
            if (isMatch(pattern, str))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断url是否与规则配置: 
     * ? 表示单个字符; 
     * * 表示一层路径内的任意字符串，不可跨层级; 
     * ** 表示任意层路径;
     * 
     * @param pattern 匹配规则
     * @param url 需要匹配的url
     * @return
     */
    public static boolean isMatch(String pattern, String url)
    {
        AntPathMatcher matcher = new AntPathMatcher();
        return matcher.match(pattern, url);
    }

```

## 3. XSS过滤处理

/**
 * XSS过滤处理
 * 
 * @author lh
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper
{
    /**
     * @param request
     */
    public XssHttpServletRequestWrapper(HttpServletRequest request)
    {
        super(request);
    }

    // 重写获取参数进行转义
    @Override
    public String[] getParameterValues(String name)
    {
        String[] values = super.getParameterValues(name);
        if (values != null)
        {
            int length = values.length;
            String[] escapesValues = new String[length];
            for (int i = 0; i < length; i++)
            {
                // 防xss攻击和过滤前后空格
                escapesValues[i] = EscapeUtil.clean(values[i]).trim();
            }
            return escapesValues;
        }
        return super.getParameterValues(name);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException
    {
        // 非json类型，直接返回
        if (!isJsonRequest())
        {
            return super.getInputStream();
        }

        // 为空，直接返回
        String json = IOUtils.toString(super.getInputStream(), "utf-8");
        if (StringUtils.isEmpty(json))
        {
            return super.getInputStream();
        }

        // xss过滤
        json = EscapeUtil.clean(json).trim();
        byte[] jsonBytes = json.getBytes("utf-8");
        final ByteArrayInputStream bis = new ByteArrayInputStream(jsonBytes);
        return new ServletInputStream()
        {
            @Override
            public boolean isFinished()
            {
                return true;
            }

            @Override
            public boolean isReady()
            {
                return true;
            }

            @Override
            public int available() throws IOException
            {
                return jsonBytes.length;
            }

            @Override
            public void setReadListener(ReadListener readListener)
            {
            }

            @Override
            public int read() throws IOException
            {
                return bis.read();
            }
        };
    }

    /**
     * 是否是Json请求
     * 
     * @param request
     */
    public boolean isJsonRequest()
    {
        String header = super.getHeader(HttpHeaders.CONTENT_TYPE);
        return StringUtils.startsWithIgnoreCase(header, MediaType.APPLICATION_JSON_VALUE);
    }
}

## 4. 转义html字符 - clean方法

public static String clean(String content)
    {
        return new HTMLFilter().filter(content);
    }

## 5. 转义html字符 - html过滤器
```java
/**
 * HTML过滤器，用于去除XSS漏洞隐患。
 *
 * @author lh
 */
public final class HTMLFilter
{
    /**
     * regex flag union representing /si modifiers in php
     **/
    private static final int REGEX_FLAGS_SI = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;
    private static final Pattern P_COMMENTS = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);
    private static final Pattern P_COMMENT = Pattern.compile("^!--(.*)--$", REGEX_FLAGS_SI);
    private static final Pattern P_TAGS = Pattern.compile("<(.*?)>", Pattern.DOTALL);
    private static final Pattern P_END_TAG = Pattern.compile("^/([a-z0-9]+)", REGEX_FLAGS_SI);
    private static final Pattern P_START_TAG = Pattern.compile("^([a-z0-9]+)(.*?)(/?)$", REGEX_FLAGS_SI);
    private static final Pattern P_QUOTED_ATTRIBUTES = Pattern.compile("([a-z0-9]+)=([\"'])(.*?)\\2", REGEX_FLAGS_SI);
    private static final Pattern P_UNQUOTED_ATTRIBUTES = Pattern.compile("([a-z0-9]+)(=)([^\"\\s']+)", REGEX_FLAGS_SI);
    private static final Pattern P_PROTOCOL = Pattern.compile("^([^:]+):", REGEX_FLAGS_SI);
    private static final Pattern P_ENTITY = Pattern.compile("&#(\\d+);?");
    private static final Pattern P_ENTITY_UNICODE = Pattern.compile("&#x([0-9a-f]+);?");
    private static final Pattern P_ENCODE = Pattern.compile("%([0-9a-f]{2});?");
    private static final Pattern P_VALID_ENTITIES = Pattern.compile("&([^&;]*)(?=(;|&|$))");
    private static final Pattern P_VALID_QUOTES = Pattern.compile("(>|^)([^<]+?)(<|$)", Pattern.DOTALL);
    private static final Pattern P_END_ARROW = Pattern.compile("^>");
    private static final Pattern P_BODY_TO_END = Pattern.compile("<([^>]*?)(?=<|$)");
    private static final Pattern P_XML_CONTENT = Pattern.compile("(^|>)([^<]*?)(?=>)");
    private static final Pattern P_STRAY_LEFT_ARROW = Pattern.compile("<([^>]*?)(?=<|$)");
    private static final Pattern P_STRAY_RIGHT_ARROW = Pattern.compile("(^|>)([^<]*?)(?=>)");
    private static final Pattern P_AMP = Pattern.compile("&");
    private static final Pattern P_QUOTE = Pattern.compile("\"");
    private static final Pattern P_LEFT_ARROW = Pattern.compile("<");
    private static final Pattern P_RIGHT_ARROW = Pattern.compile(">");
    private static final Pattern P_BOTH_ARROWS = Pattern.compile("<>");

    // @xxx could grow large... maybe use sesat's ReferenceMap
    private static final ConcurrentMap<String, Pattern> P_REMOVE_PAIR_BLANKS = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Pattern> P_REMOVE_SELF_BLANKS = new ConcurrentHashMap<>();

    /**
     * set of allowed html elements, along with allowed attributes for each element
     **/
    private final Map<String, List<String>> vAllowed;
    /**
     * counts of open tags for each (allowable) html element
     **/
    private final Map<String, Integer> vTagCounts = new HashMap<>();

    /**
     * html elements which must always be self-closing (e.g. "<img />")
     **/
    private final String[] vSelfClosingTags;
    /**
     * html elements which must always have separate opening and closing tags (e.g. "<b></b>")
     **/
    private final String[] vNeedClosingTags;
    /**
     * set of disallowed html elements
     **/
    private final String[] vDisallowed;
    /**
     * attributes which should be checked for valid protocols
     **/
    private final String[] vProtocolAtts;
    /**
     * allowed protocols
     **/
    private final String[] vAllowedProtocols;
    /**
     * tags which should be removed if they contain no content (e.g. "<b></b>" or "<b />")
     **/
    private final String[] vRemoveBlanks;
    /**
     * entities allowed within html markup
     **/
    private final String[] vAllowedEntities;
    /**
     * flag determining whether comments are allowed in input String.
     */
    private final boolean stripComment;
    private final boolean encodeQuotes;
    /**
     * flag determining whether to try to make tags when presented with "unbalanced" angle brackets (e.g. "<b text </b>"
     * becomes "<b> text </b>"). If set to false, unbalanced angle brackets will be html escaped.
     */
    private final boolean alwaysMakeTags;

    /**
     * Default constructor.
     */
    public HTMLFilter()
    {
        vAllowed = new HashMap<>();

        final ArrayList<String> a_atts = new ArrayList<>();
        a_atts.add("href");
        a_atts.add("target");
        vAllowed.put("a", a_atts);

        final ArrayList<String> img_atts = new ArrayList<>();
        img_atts.add("src");
        img_atts.add("width");
        img_atts.add("height");
        img_atts.add("alt");
        vAllowed.put("img", img_atts);

        final ArrayList<String> no_atts = new ArrayList<>();
        vAllowed.put("b", no_atts);
        vAllowed.put("strong", no_atts);
        vAllowed.put("i", no_atts);
        vAllowed.put("em", no_atts);

        vSelfClosingTags = new String[] { "img" };
        vNeedClosingTags = new String[] { "a", "b", "strong", "i", "em" };
        vDisallowed = new String[] {};
        vAllowedProtocols = new String[] { "http", "mailto", "https" }; // no ftp.
        vProtocolAtts = new String[] { "src", "href" };
        vRemoveBlanks = new String[] { "a", "b", "strong", "i", "em" };
        vAllowedEntities = new String[] { "amp", "gt", "lt", "quot" };
        stripComment = true;
        encodeQuotes = true;
        alwaysMakeTags = false;
    }

    /**
     * Map-parameter configurable constructor.
     *
     * @param conf map containing configuration. keys match field names.
     */
    @SuppressWarnings("unchecked")
    public HTMLFilter(final Map<String, Object> conf)
    {

        assert conf.containsKey("vAllowed") : "configuration requires vAllowed";
        assert conf.containsKey("vSelfClosingTags") : "configuration requires vSelfClosingTags";
        assert conf.containsKey("vNeedClosingTags") : "configuration requires vNeedClosingTags";
        assert conf.containsKey("vDisallowed") : "configuration requires vDisallowed";
        assert conf.containsKey("vAllowedProtocols") : "configuration requires vAllowedProtocols";
        assert conf.containsKey("vProtocolAtts") : "configuration requires vProtocolAtts";
        assert conf.containsKey("vRemoveBlanks") : "configuration requires vRemoveBlanks";
        assert conf.containsKey("vAllowedEntities") : "configuration requires vAllowedEntities";

        vAllowed = Collections.unmodifiableMap((HashMap<String, List<String>>) conf.get("vAllowed"));
        vSelfClosingTags = (String[]) conf.get("vSelfClosingTags");
        vNeedClosingTags = (String[]) conf.get("vNeedClosingTags");
        vDisallowed = (String[]) conf.get("vDisallowed");
        vAllowedProtocols = (String[]) conf.get("vAllowedProtocols");
        vProtocolAtts = (String[]) conf.get("vProtocolAtts");
        vRemoveBlanks = (String[]) conf.get("vRemoveBlanks");
        vAllowedEntities = (String[]) conf.get("vAllowedEntities");
        stripComment = conf.containsKey("stripComment") ? (Boolean) conf.get("stripComment") : true;
        encodeQuotes = conf.containsKey("encodeQuotes") ? (Boolean) conf.get("encodeQuotes") : true;
        alwaysMakeTags = conf.containsKey("alwaysMakeTags") ? (Boolean) conf.get("alwaysMakeTags") : true;
    }

    private void reset()
    {
        vTagCounts.clear();
    }

    // ---------------------------------------------------------------
    // my versions of some PHP library functions
    public static String chr(final int decimal)
    {
        return String.valueOf((char) decimal);
    }

    public static String htmlSpecialChars(final String s)
    {
        String result = s;
        result = regexReplace(P_AMP, "&amp;", result);
        result = regexReplace(P_QUOTE, "&quot;", result);
        result = regexReplace(P_LEFT_ARROW, "&lt;", result);
        result = regexReplace(P_RIGHT_ARROW, "&gt;", result);
        return result;
    }

    // ---------------------------------------------------------------

    /**
     * given a user submitted input String, filter out any invalid or restricted html.
     *
     * @param input text (i.e. submitted by a user) than may contain html
     * @return "clean" version of input, with only valid, whitelisted html elements allowed
     */
    public String filter(final String input)
    {
        reset();
        String s = input;

        s = escapeComments(s);

        s = balanceHTML(s);

        s = checkTags(s);

        s = processRemoveBlanks(s);

        // s = validateEntities(s);

        return s;
    }

    public boolean isAlwaysMakeTags()
    {
        return alwaysMakeTags;
    }

    public boolean isStripComments()
    {
        return stripComment;
    }

    private String escapeComments(final String s)
    {
        final Matcher m = P_COMMENTS.matcher(s);
        final StringBuffer buf = new StringBuffer();
        if (m.find())
        {
            final String match = m.group(1); // (.*?)
            m.appendReplacement(buf, Matcher.quoteReplacement("<!--" + htmlSpecialChars(match) + "-->"));
        }
        m.appendTail(buf);

        return buf.toString();
    }

    private String balanceHTML(String s)
    {
        if (alwaysMakeTags)
        {
            //
            // try and form html
            //
            s = regexReplace(P_END_ARROW, "", s);
            // 不追加结束标签
            s = regexReplace(P_BODY_TO_END, "<$1>", s);
            s = regexReplace(P_XML_CONTENT, "$1<$2", s);

        }
        else
        {
            //
            // escape stray brackets
            //
            s = regexReplace(P_STRAY_LEFT_ARROW, "&lt;$1", s);
            s = regexReplace(P_STRAY_RIGHT_ARROW, "$1$2&gt;<", s);

            //
            // the last regexp causes '<>' entities to appear
            // (we need to do a lookahead assertion so that the last bracket can
            // be used in the next pass of the regexp)
            //
            s = regexReplace(P_BOTH_ARROWS, "", s);
        }

        return s;
    }

    private String checkTags(String s)
    {
        Matcher m = P_TAGS.matcher(s);

        final StringBuffer buf = new StringBuffer();
        while (m.find())
        {
            String replaceStr = m.group(1);
            replaceStr = processTag(replaceStr);
            m.appendReplacement(buf, Matcher.quoteReplacement(replaceStr));
        }
        m.appendTail(buf);

        // these get tallied in processTag
        // (remember to reset before subsequent calls to filter method)
        final StringBuilder sBuilder = new StringBuilder(buf.toString());
        for (String key : vTagCounts.keySet())
        {
            for (int ii = 0; ii < vTagCounts.get(key); ii++)
            {
                sBuilder.append("</").append(key).append(">");
            }
        }
        s = sBuilder.toString();

        return s;
    }

    private String processRemoveBlanks(final String s)
    {
        String result = s;
        for (String tag : vRemoveBlanks)
        {
            if (!P_REMOVE_PAIR_BLANKS.containsKey(tag))
            {
                P_REMOVE_PAIR_BLANKS.putIfAbsent(tag, Pattern.compile("<" + tag + "(\\s[^>]*)?></" + tag + ">"));
            }
            result = regexReplace(P_REMOVE_PAIR_BLANKS.get(tag), "", result);
            if (!P_REMOVE_SELF_BLANKS.containsKey(tag))
            {
                P_REMOVE_SELF_BLANKS.putIfAbsent(tag, Pattern.compile("<" + tag + "(\\s[^>]*)?/>"));
            }
            result = regexReplace(P_REMOVE_SELF_BLANKS.get(tag), "", result);
        }

        return result;
    }

    private static String regexReplace(final Pattern regex_pattern, final String replacement, final String s)
    {
        Matcher m = regex_pattern.matcher(s);
        return m.replaceAll(replacement);
    }

    private String processTag(final String s)
    {
        // ending tags
        Matcher m = P_END_TAG.matcher(s);
        if (m.find())
        {
            final String name = m.group(1).toLowerCase();
            if (allowed(name))
            {
                if (!inArray(name, vSelfClosingTags))
                {
                    if (vTagCounts.containsKey(name))
                    {
                        vTagCounts.put(name, vTagCounts.get(name) - 1);
                        return "</" + name + ">";
                    }
                }
            }
        }

        // starting tags
        m = P_START_TAG.matcher(s);
        if (m.find())
        {
            final String name = m.group(1).toLowerCase();
            final String body = m.group(2);
            String ending = m.group(3);

            // debug( "in a starting tag, name='" + name + "'; body='" + body + "'; ending='" + ending + "'" );
            if (allowed(name))
            {
                final StringBuilder params = new StringBuilder();

                final Matcher m2 = P_QUOTED_ATTRIBUTES.matcher(body);
                final Matcher m3 = P_UNQUOTED_ATTRIBUTES.matcher(body);
                final List<String> paramNames = new ArrayList<>();
                final List<String> paramValues = new ArrayList<>();
                while (m2.find())
                {
                    paramNames.add(m2.group(1)); // ([a-z0-9]+)
                    paramValues.add(m2.group(3)); // (.*?)
                }
                while (m3.find())
                {
                    paramNames.add(m3.group(1)); // ([a-z0-9]+)
                    paramValues.add(m3.group(3)); // ([^\"\\s']+)
                }

                String paramName, paramValue;
                for (int ii = 0; ii < paramNames.size(); ii++)
                {
                    paramName = paramNames.get(ii).toLowerCase();
                    paramValue = paramValues.get(ii);

                    // debug( "paramName='" + paramName + "'" );
                    // debug( "paramValue='" + paramValue + "'" );
                    // debug( "allowed? " + vAllowed.get( name ).contains( paramName ) );

                    if (allowedAttribute(name, paramName))
                    {
                        if (inArray(paramName, vProtocolAtts))
                        {
                            paramValue = processParamProtocol(paramValue);
                        }
                        params.append(' ').append(paramName).append("=\\\"").append(paramValue).append("\\\"");
                    }
                }

                if (inArray(name, vSelfClosingTags))
                {
                    ending = " /";
                }

                if (inArray(name, vNeedClosingTags))
                {
                    ending = "";
                }

                if (ending == null || ending.length() < 1)
                {
                    if (vTagCounts.containsKey(name))
                    {
                        vTagCounts.put(name, vTagCounts.get(name) + 1);
                    }
                    else
                    {
                        vTagCounts.put(name, 1);
                    }
                }
                else
                {
                    ending = " /";
                }
                return "<" + name + params + ending + ">";
            }
            else
            {
                return "";
            }
        }

        // comments
        m = P_COMMENT.matcher(s);
        if (!stripComment && m.find())
        {
            return "<" + m.group() + ">";
        }

        return "";
    }

    private String processParamProtocol(String s)
    {
        s = decodeEntities(s);
        final Matcher m = P_PROTOCOL.matcher(s);
        if (m.find())
        {
            final String protocol = m.group(1);
            if (!inArray(protocol, vAllowedProtocols))
            {
                // bad protocol, turn into local anchor link instead
                s = "#" + s.substring(protocol.length() + 1);
                if (s.startsWith("#//"))
                {
                    s = "#" + s.substring(3);
                }
            }
        }

        return s;
    }

    private String decodeEntities(String s)
    {
        StringBuffer buf = new StringBuffer();

        Matcher m = P_ENTITY.matcher(s);
        while (m.find())
        {
            final String match = m.group(1);
            final int decimal = Integer.decode(match).intValue();
            m.appendReplacement(buf, Matcher.quoteReplacement(chr(decimal)));
        }
        m.appendTail(buf);
        s = buf.toString();

        buf = new StringBuffer();
        m = P_ENTITY_UNICODE.matcher(s);
        while (m.find())
        {
            final String match = m.group(1);
            final int decimal = Integer.valueOf(match, 16).intValue();
            m.appendReplacement(buf, Matcher.quoteReplacement(chr(decimal)));
        }
        m.appendTail(buf);
        s = buf.toString();

        buf = new StringBuffer();
        m = P_ENCODE.matcher(s);
        while (m.find())
        {
            final String match = m.group(1);
            final int decimal = Integer.valueOf(match, 16).intValue();
            m.appendReplacement(buf, Matcher.quoteReplacement(chr(decimal)));
        }
        m.appendTail(buf);
        s = buf.toString();

        s = validateEntities(s);
        return s;
    }

    private String validateEntities(final String s)
    {
        StringBuffer buf = new StringBuffer();

        // validate entities throughout the string
        Matcher m = P_VALID_ENTITIES.matcher(s);
        while (m.find())
        {
            final String one = m.group(1); // ([^&;]*)
            final String two = m.group(2); // (?=(;|&|$))
            m.appendReplacement(buf, Matcher.quoteReplacement(checkEntity(one, two)));
        }
        m.appendTail(buf);

        return encodeQuotes(buf.toString());
    }

    private String encodeQuotes(final String s)
    {
        if (encodeQuotes)
        {
            StringBuffer buf = new StringBuffer();
            Matcher m = P_VALID_QUOTES.matcher(s);
            while (m.find())
            {
                final String one = m.group(1); // (>|^)
                final String two = m.group(2); // ([^<]+?)
                final String three = m.group(3); // (<|$)
                // 不替换双引号为&quot;，防止json格式无效 regexReplace(P_QUOTE, "&quot;", two)
                m.appendReplacement(buf, Matcher.quoteReplacement(one + two + three));
            }
            m.appendTail(buf);
            return buf.toString();
        }
        else
        {
            return s;
        }
    }

    private String checkEntity(final String preamble, final String term)
    {

        return ";".equals(term) && isValidEntity(preamble) ? '&' + preamble : "&amp;" + preamble;
    }

    private boolean isValidEntity(final String entity)
    {
        return inArray(entity, vAllowedEntities);
    }

    private static boolean inArray(final String s, final String[] array)
    {
        for (String item : array)
        {
            if (item != null && item.equals(s))
            {
                return true;
            }
        }
        return false;
    }

    private boolean allowed(final String name)
    {
        return (vAllowed.isEmpty() || vAllowed.containsKey(name)) && !inArray(name, vDisallowed);
    }

    private boolean allowedAttribute(final String name, final String paramName)
    {
        return allowed(name) && (vAllowed.isEmpty() || vAllowed.get(name).contains(paramName));
    }
}
```

## 6. 注册配置过滤器bean - 注册bean

```java
@Configuration
public class FilterConfig
{
    @Value("${xss.excludes}")
    private String excludes;

    @Value("${xss.urlPatterns}")
    private String urlPatterns;

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Bean
    @ConditionalOnProperty(value = "xss.enabled", havingValue = "true")
    public FilterRegistrationBean xssFilterRegistration()
    {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setDispatcherTypes(DispatcherType.REQUEST);
        registration.setFilter(new XssFilter());
        //添加过滤路径
        registration.addUrlPatterns(StringUtils.split(urlPatterns, ","));
        registration.setName("xssFilter");
        registration.setOrder(FilterRegistrationBean.HIGHEST_PRECEDENCE);
        //设置初始化参数
        Map<String, String> initParameters = new HashMap<String, String>();
        initParameters.put("excludes", excludes);
        registration.setInitParameters(initParameters);
        return registration;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Bean
    public FilterRegistrationBean someFilterRegistration()
    {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new RepeatableFilter());
        registration.addUrlPatterns("/*");
        registration.setName("repeatableFilter");
        registration.setOrder(FilterRegistrationBean.LOWEST_PRECEDENCE);
        return registration;
    }

}
```

## 7. 注册配置过滤器bean - 文件配置
```java
# 防止XSS攻击
xss:
  # 过滤开关
  enabled: true
  # 排除链接（多个用逗号分隔）
  excludes: /system/notice
  # 匹配链接
  urlPatterns: /system/*,/monitor/*,/tool/*
```

## 8. 转义和反转义工具
```java
/**
 * 转义和反转义工具类
 * 
 * @author lh
 */
public class EscapeUtil
{
    public static final String RE_HTML_MARK = "(<[^<]*?>)|(<[\\s]*?/[^<]*?>)|(<[^<]*?/[\\s]*?>)";

    private static final char[][] TEXT = new char[64][];

    static
    {
        for (int i = 0; i < 64; i++)
        {
            TEXT[i] = new char[] { (char) i };
        }

        // special HTML characters
        TEXT['\''] = "&#039;".toCharArray(); // 单引号
        TEXT['"'] = "&#34;".toCharArray(); // 双引号
        TEXT['&'] = "&#38;".toCharArray(); // &符
        TEXT['<'] = "&#60;".toCharArray(); // 小于号
        TEXT['>'] = "&#62;".toCharArray(); // 大于号
    }

    /**
     * 转义文本中的HTML字符为安全的字符
     * 
     * @param text 被转义的文本
     * @return 转义后的文本
     */
    public static String escape(String text)
    {
        return encode(text);
    }

    /**
     * 还原被转义的HTML特殊字符
     * 
     * @param content 包含转义符的HTML内容
     * @return 转换后的字符串
     */
    public static String unescape(String content)
    {
        return decode(content);
    }

    /**
     * 清除所有HTML标签，但是不删除标签内的内容
     * 
     * @param content 文本
     * @return 清除标签后的文本
     */
    public static String clean(String content)
    {
        return new HTMLFilter().filter(content);
    }

    /**
     * Escape编码
     * 
     * @param text 被编码的文本
     * @return 编码后的字符
     */
    private static String encode(String text)
    {
        if (StringUtils.isEmpty(text))
        {
            return StringUtils.EMPTY;
        }

        final StringBuilder tmp = new StringBuilder(text.length() * 6);
        char c;
        for (int i = 0; i < text.length(); i++)
        {
            c = text.charAt(i);
            if (c < 256)
            {
                tmp.append("%");
                if (c < 16)
                {
                    tmp.append("0");
                }
                tmp.append(Integer.toString(c, 16));
            }
            else
            {
                tmp.append("%u");
                if (c <= 0xfff)
                {
                    // issue#I49JU8@Gitee
                    tmp.append("0");
                }
                tmp.append(Integer.toString(c, 16));
            }
        }
        return tmp.toString();
    }

    /**
     * Escape解码
     * 
     * @param content 被转义的内容
     * @return 解码后的字符串
     */
    public static String decode(String content)
    {
        if (StringUtils.isEmpty(content))
        {
            return content;
        }

        StringBuilder tmp = new StringBuilder(content.length());
        int lastPos = 0, pos = 0;
        char ch;
        while (lastPos < content.length())
        {
            pos = content.indexOf("%", lastPos);
            if (pos == lastPos)
            {
                if (content.charAt(pos + 1) == 'u')
                {
                    ch = (char) Integer.parseInt(content.substring(pos + 2, pos + 6), 16);
                    tmp.append(ch);
                    lastPos = pos + 6;
                }
                else
                {
                    ch = (char) Integer.parseInt(content.substring(pos + 1, pos + 3), 16);
                    tmp.append(ch);
                    lastPos = pos + 3;
                }
            }
            else
            {
                if (pos == -1)
                {
                    tmp.append(content.substring(lastPos));
                    lastPos = content.length();
                }
                else
                {
                    tmp.append(content.substring(lastPos, pos));
                    lastPos = pos;
                }
            }
        }
        return tmp.toString();
    }

    public static void main(String[] args)
    {
        String html = "<script>alert(1);</script>";
        String escape = EscapeUtil.escape(html);
        // String html = "<scr<script>ipt>alert(\"XSS\")</scr<script>ipt>";
        // String html = "<123";
        // String html = "123>";
        System.out.println("clean: " + EscapeUtil.clean(html));
        System.out.println("escape: " + escape);
        System.out.println("unescape: " + EscapeUtil.unescape(escape));
    }
```

## 9. 测试类

```java
@Slf4j
@RestController
public class XssController {

    //键值对
    @PostMapping("xssFilter")
    public String xssFilter(String name, String info) {
        log.error(name + "---" + info);
        return name + "---" + info;
    }
    //实体
    @PostMapping("modelXssFilter")
    public People modelXssFilter(@RequestBody UserEntity user) {
        log.error(user.getUserName() + "---" + user.getMobile());
        return user;
    }

    //不转义
    @PostMapping("open/xssFilter")
    public String openXssFilter(String name) {
        return name;
    }

    //不转义2
    @PostMapping("open2/xssFilter")
    public String open2XssFilter(String name) {
        return name;
    }
    
    // 这里最好单独建立实体，这里这里只是演示
    @ApiModel(value = "UserEntity", description = "用户实体")
class UserEntity
{
    @ApiModelProperty("用户ID")
    private Integer userId;

    @ApiModelProperty("用户名称")
    private String username;

    @ApiModelProperty("用户密码")
    private String password;

    @ApiModelProperty("用户手机")
    private String mobile;

    public UserEntity()
    {

    }

    public UserEntity(Integer userId, String username, String password, String mobile)
    {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.mobile = mobile;
    }

    public Integer getUserId()
    {
        return userId;
    }

    public void setUserId(Integer userId)
    {
        this.userId = userId;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getPassword()
    {
        return password;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public String getMobile()
    {
        return mobile;
    }

    public void setMobile(String mobile)
    {
        this.mobile = mobile;
    }
}
}
```

</font>
