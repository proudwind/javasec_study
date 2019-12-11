# java代码审计-xss

## 0x01 漏洞挖掘

```java
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    response.setContentType("text/html");
    String content = request.getParameter("content");
    request.setAttribute("content", content);
    request.getRequestDispatcher("/WEB-INF/pages/xss.jsp").forward(request, response);
}
```

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Xss Test</title>
</head>
<body>
<div>
    ${content}
</div>
</body>
</html>
```

一个简单的小demo，xss本质上就是浏览器执行了域外的代码，出现的场景比较多，需要具体情况具体分析

## 0x02 漏洞防御

可以使用esapi的encoder

```java
import org.owasp.esapi.ESAPI;

String content = request.getParameter("content");
content = ESAPI.encoder().encodeForHTML(content);
content = ESAPI.encoder().encoderForJavaScript(content); //防御dom xss使用jsencode
```

也可以自行进行htmlencode

```java
import org.apache.commons.lang.StringUtils;

private String htmlEncode(String content) {
    content = StringUtils.replace(content, "&", "&amp;");
    content = StringUtils.replace(content, "<", "&lt;");
    content = StringUtils.replace(content, ">", "&gt;");
    content = StringUtils.replace(content, "\"", "&quot;");
    content = StringUtils.replace(content, "'", "&#x27;");
    content = StringUtils.replace(content, "/", "&#x2F;");
    return content;
}
```

## 0x03 参考链接

[http://liehu.tass.com.cn/archives/1427](http://liehu.tass.com.cn/archives/1427)