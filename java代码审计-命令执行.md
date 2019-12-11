# java代码审计-命令执行

## 0x01 漏洞挖掘

```java
String cmd = request.getParameter("cmd");
Runtime runtime = Runtime.getRuntime(); //Runtime.getRuntime.exec
ProcessBuilder processBuilder = new ProcessBuilder(cmd); //ProcessBuilder.start()

String result = "";
try {
  //Process process = runtime.exec(cmd);
  Process process = processBuilder.start();
  //只是调用了对应进程没有回显，需要从流中读取
  BufferedInputStream bis = new BufferedInputStream(process.getInputStream());
  BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(bis));
  String line = "";
  while (null != (line = bufferedReader.readLine())) {
    result += line + "\n";
  }
  if (process.waitFor() != 0) {
    if (process.exitValue() == 1)
      response.getWriter().println("command exec failed");
  }
  bufferedInputStream.close();
  bufferedReader.close();
} catch (Exception e) {
  response.getWriter().println("error");
  return;
}
response.getWriter().println(result);
```

java的`Runtime.getRuntime.exec`和`ProcessBuilder.start`，都是直接启动传入参数对应的进程。以curl为例，php的`system`会启动系统shell，然后通过shell来启动curl进程，这个过程中，如果传入的命令带有shell能解析的语法，就会首先解析。

所以，如果只是命令执行的部分参数可控，想在java中通过`;、|、&`等实现命令注入，是行不通的。当然不排除程序本身存在漏洞，只需传入参数即可造成漏洞。

如果命令以字符串形式传入`Runtime.getRuntime.exec`，程序会将传入的命令用空格来拆分。

```java
Process process = runtime.exec("ping -c 1 " + ip);
//这种传入 127.0.0.1 | id，是无法正常执行的
```

如果执行命令使用的是`ProcessBuilder.start`，那么只能执行无参数的命令。因为`ProcessBuilder`不支持以字符串形式传入命令，只能拆分成List或者数组的形式传入，才能执行。

如果参数完全可控，可自行启动shell，然后在执行命令。

```java
Process process = runtime.exec("sh -c whoami");
```

## 0x02 漏洞防御

命令执行漏洞的防御需要结合实际场景，没有很通用的防御手段。

1. 尽量避免调用shell来执行命令。
2. 如果是拼接参数来执行命令，对参数进行严格过滤，比如只允许字母数字。

## 0x03 参考资料

[https://b1ngz.github.io/java-os-command-injection-note/](https://b1ngz.github.io/java-os-command-injection-note/)

[https://blog.csdn.net/u013256816/article/details/54603910](https://blog.csdn.net/u013256816/article/details/54603910)

[https://mp.weixin.qq.com/s/zCe_O37rdRqgN-Yvlq1FDg](https://mp.weixin.qq.com/s/zCe_O37rdRqgN-Yvlq1FDg)