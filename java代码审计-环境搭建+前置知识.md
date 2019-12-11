# Java代码审计-环境搭建+前置知识

## 0x00 中间件

### tomcat

因为个人比较矫情，不想在mac搭java的开发环境，就想着有没有本地写代码然后部署到虚拟机上运行。毕竟java是静态语言，在编译阶段就能找出一大部分错误。

#### remote server

首先使用idea新建一个tomcat remote server

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190312171729.png)

注意mapped as那里填远程主机的tomcat webapps目录的位置。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190312172141.png)

然后选择idea与服务器连接的方式，这里我选择了sftp，并且新建了一个tomcat用户便于权限控制。

接着进行服务器端的配置，在catalina.sh开头添加如下内容：

```sh
export CATALINA_OPTS="-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.port=10999 #与上图中JMX port的值相同
-Dcom.sun.management.jmxremote.ssl=false
-Dcom.sun.management.jmxremote.authenticate=false
-Djava.rmi.server.hostname=172.16.72.131" #服务器地址

export JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=64695 $JAVA_OPTS" #开放debug端口，用于远程调试。最后一定要加$JAVA_OPTS，否则会覆盖掉前面的配置。

export JAVA_OPTS="-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.port=10999
-Dcom.sun.management.jmxremote.ssl=false
-Dcom.sun.management.jmxremote.authenticate=false $JAVA_OPTS" 
```

如果有`Error: Password file not found: /xxxx/jmxremote.password`，则需要在对应目录创建`jmxremote.password`。

```sh
touch jmxremote.password
chmod 600 jmxremote.password #必须严格控制权限，否则tomcat会报错
chown tomcat:tomcat jmxremote.password	#修改文件用户组
```

这样就可以愉快的把代码上传到服务器部署了，远程调试也没有问题。但是马上就会发现一个很致命的问题——不能热更新。。。搜索半天，找到一个解决方案——**jrebel**。

#### remote server支持热更新

首先需要在idea中安装jrebel插件，这个网上有很多教程。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190312173933.png)

根据提示一步一步来就好了，这里很坑的一个点，就是第三步并没有定义jrebel的连接端口，个人的catalina-jrebel.sh内容如下：

```sh
#!/bin/bash
export REBEL_HOME="/home/tomcat/jrebel"
export JAVA_OPTS="\"-agentpath:$REBEL_HOME/lib/libjrebel64.so\" -Drebel.remoting_plugin=true -Drebel.remoting_port=8081 $JAVA_OPTS" #一定要定义一个remoting_port
`dirname $0`/catalina.sh $@
```

之后将catalina.sh相关操作替换为catalina-jrebel.sh就可以了，现在写完代码只要重新编译一次，就会自动同步到服务器上，实现热更新。

## 0x01 Jsp + Servlet + JDBC

项目依赖使用maven管理，首先来看最基本的java web技术。

一开始会将servlet的相关配置放在web.xml中，代码审计也需要从这个文件入手，对整个项目由一个整体把握。

```xml
<servlet>
        <servlet-name>UserServlet</servlet-name>
        <servlet-class>com.bfshop.servlet.UserServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>UserServlet</servlet-name>
  <url-pattern>/user</url-pattern>
</servlet-mapping>
```

在servlet3之后，可以用注解带代替xml中的配置。

```java
@WebServlet(name = "XssServlet", value = "/xss")
public class XssServlet extends HttpServlet {}
```

### filter

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190321003230.png)

多个filter的拦截顺序和`<filter-mapping>`的配置顺序有关。这里写一个最简单的demo，将所有页面的编码设为utf-8。

```xml
<filter>
  <filter-name>Filter0Encode</filter-name>
  <filter-class>cn.seaii.vulnjsm.filter.Filter0Encode</filter-class>
</filter>
<filter-mapping>
  <filter-name>Filter0Encode</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

```java
public class Filter0Encode implements Filter { //必须实现Filter接口
    public void destroy() {
    }

  	//由该方法对请求进行拦截
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        req.setCharacterEncoding("utf-8"); //设置编码
        chain.doFilter(req, resp); //放行，进入下一个filter或者目标页面
    }

		//private FilterConfig filterConfig;
  	//如果需要读取配置，可获取config参数
    public void init(FilterConfig config) throws ServletException {
				//this.filterConfig = config;
    }
}
```

同样，在servlet3之后支持以注解的形式来定义servlet。通过注解定义的filter，执行顺序是通过**filter类名的首字母**来判断的。

```java
@WebFilter(filterName = "Filter0Encode", urlPatterns = {"/*"})
public class Filter0Encode implements Filter {}
```

### listener

略

## 0x02 Spring

虽然这些东西已经被翻来覆去的快说烂了，但还是要记录一下。

spring的并不是一个新的web框架，而是作者认为java的框架已经足够多且功能完善，只需要一个“工具”将他们整合起来即可，因此spring诞生了。

Spring最重要的两个思想IOC(DI)和AOP：

* IOC(DI)即控制反转（依赖注入），这里的控制指的是对类实例化的控制，反转是指通常类的实例化是由开发人员完成的，现在将这个权利给予容器（这里就是spring），告诉容器实例化类的方法，在使用时可以直接调用，降低的代码的耦合度和量，同时也增加了程序的可读性。
* AOP即面向切面编程，思想与中类似（其实我不知道谁先谁后），简单理解就是将各个模块公用的模块（如打日志）抽出来，也可以降低代码的耦合度。

## 0x03 Springboot

啥也不说了，springboot天下第一。