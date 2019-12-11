# java代码审计-表达式注入

## 0x01漏洞挖掘

### spel

spel表达式有三种用法：

1. 注解

   ```java
   @value("#{表达式}")
   public String arg;
   ```

   这种一般是写死在代码中的，不是关注的重点。

2. xml

   ```xml
   <bean id="Bean1" class="com.test.xxx">
   	<property name="arg" value="#{表达式}">
   </bean>
   ```

   这种情况通常也是写死在代码中的，但是也有已知的利用场景，就是利用反序列化让程序加载我们实现构造好的恶意xml文件，如jackson的CVE-2017-17485、weblogic的CVE-2019-2725等。

3. 在代码中处理外部传入的表达式

   这部分是关注的重点。

   ```java
   @RequestMapping("/spel")
   public String spel(@RequestParam(name = "spel") String spel) {
       ExpressionParser expressionParser = new SpelExpressionParser();
       Expression expression = expressionParser.parseExpression(spel);
       Object object = expression.getValue();
       return object.toString();
   }
   ```

漏洞可以利用的前置条件有三个：

1. 传入的表达式为过滤
2. 表达式解析之后调用了**getValue/setValue**方法
3. 使用**StandardEvaluationContext**（默认）作为上下文对象

spel表达式功能非常强大，在漏洞利用方面主要使用这几个功能：

* 使用T(Type)表示Type类的实例,Type为全限定名称,如T(com.test.Bean1)。但是java.lang例外,该包下的类可以不指定包名。得到类实例后会访问类静态方法与字段。

  ```java
  T(java.lang.Runtime).getRuntime().exec("whoami")
  ```

* 直接通过java语法实例化对象、调用方法

  ```java
  new ProcessBuilder("whoami").start()
  
  //可以利用反射来绕过一些过滤
  #{''.getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('ex'+'ec',''.getClass()).invoke(''.getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('getRu'+'ntime').invoke(null),'calc')}
  ```

### jexl

关于jexl，比较有代表性的就是前段时间Nexus的rce，[Nexus Repository Manager 3 RCE 分析 -【CVE-2019-7238】](https://xz.aliyun.com/t/4136)文章在这，不再赘述。

### 其它

还有其它种类的表达式，如EL，不会轻易造成安全问题，暂时略过；OGNL表达式会在struts2相关的漏洞中详细说明。

## 0x02漏洞防御

1. 最简单的方式，使用**SimpleEvaluationContext**作为上下文对象。

   ```java
   @RequestMapping("/spel")
   public String spel(@RequestParam(name = "spel") String spel) {
       ExpressionParser expressionParser = new SpelExpressionParser();
       Expression expression = expressionParser.parseExpression(spel);
     	
     	//SimpleEvaluationContext减少了一部分功能，并在权限控制上进一步细化
     	//可以配置让spel表达式只能访问指定对象
     	Category category = new Category();
       EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(category).build();
     
       Object object = expression.getValue();
       return object.toString();
   }
   ```

2. 如果SimpleEvaluationContext不能满足需求，就需要对输入进行严格的过滤。

## 0x03参考链接

[SpEL表达式注入](https://p0rz9.github.io/2019/05/28/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5/)

[Java特色-表达式注入漏洞从入门到放弃](https://aluvion.github.io/2019/04/25/Java%E7%89%B9%E8%89%B2-%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E6%94%BE%E5%BC%83/)

[Nexus Repository Manager 3 RCE 分析 -【CVE-2019-7238】](https://xz.aliyun.com/t/4136)