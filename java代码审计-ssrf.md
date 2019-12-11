# java代码审计-ssrf

## 0x01 漏洞挖掘

java发送http请求的方式还是比较多的，下面是原生的：

```java
String url = request.getParameter("url");
URL u = new URL(url);

//1.URL，直接打开，可以跨协议
InputStream inputStream = u.openStream();

//2. URLConnection，使用这种方法发送请求可以跨协议
URLConnection urlConnection = u.openConnection();
//3. HttpURLConnection，进行类型转换之后，只允许http/https
HttpURLConnection httpURLConnection = (HttpURLConnection)urlConnection;
InputStream inputStream = urlConnection.getInputStream();

//处理请求结果
BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
String inputLine;
StringBuilder html = new StringBuilder();
while ((inputLine = bufferedReader.readLine()) != null) {
  html.append(inputLine);
}
response.getWriter().println("html:" + html.toString());
bufferedReader.close();

//4. ImageIO，如果获取到的不是图片，会返回null
BufferedImage img = ImageIO.read(u);
```

还有一部分第三方类库的：

```java
// Request漏洞示例
String url = request.getParameter("url");
return Request.Get(url).execute().returnContent().toString();//发起请求

// OkHttpClient漏洞示例
String url = request.getParameter("url");
OkHttpClient client = new OkHttpClient();
com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(url).build();
client.newCall(ok_http).execute();  //发起请求

// HttpClients漏洞示例
String url = request.getParameter("url");
CloseableHttpClient client = HttpClients.createDefault();
HttpGet httpGet = new HttpGet(url);
HttpResponse httpResponse = client.execute(httpGet); //发起请求
```

## 0x02 漏洞防御

关于ssrf的防御，p牛已经给出了比较完善的解决方案[谈一谈如何在Python开发中拒绝SSRF漏洞](https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html)。

总结下来无非是这么几点：

1. 正确处理302跳转（在业务角度看，不能直接禁止302，而是对跳转的地址重新进行检查）
2. 限制协议只能为http/https，防止跨协议
3. 设置内网ip黑名单（正确判定内网ip、正确获取host）
4. 设置常见web端口白名单（防止端口扫描，可能业务受限比较大）

```java
private static int connectTime = 5 * 1000;

public static boolean checkSsrf(String url) {
  HttpURLConnection httpURLConnection;
  String finalUrl = url;
  try {
    do {
      if(!Pattern.matches("^https?://.*/.*$", finalUrl)) { //只允许http/https协议
        return false;
      }
      if(isInnerIp(url)) { //判断是否为内网ip
        return false;
      }

      httpURLConnection = (HttpURLConnection) new URL(finalUrl).openConnection();
      httpURLConnection.setInstanceFollowRedirects(false); //不跟随跳转
      httpURLConnection.setUseCaches(false); //不使用缓存
      httpURLConnection.setConnectTimeout(connectTime); //设置超时时间
      httpURLConnection.connect(); //send dns request

      int statusCode = httpURLConnection.getResponseCode();
      if (statusCode >= 300 && statusCode <=307 && statusCode != 304 && statusCode != 306) {
        String redirectedUrl = httpURLConnection.getHeaderField("Location");
        if (null == redirectedUrl)
          break;
        finalUrl = redirectedUrl; //获取到跳转之后的url，再次进行判断
      } else {
        break;
      }
    } while (httpURLConnection.getResponseCode() != HttpURLConnection.HTTP_OK);//如果没有返回200，继续对跳转后的链接进行检查
    httpURLConnection.disconnect();
  } catch (Exception e) {
    return true;
  }
  return true;
}

private static boolean isInnerIp(String url) throws URISyntaxException, UnknownHostException {
    URI uri = new URI(url);
    String host = uri.getHost(); //url转host
  	//这一步会发送dns请求，host转ip，各种进制也会转化为常见的x.x.x.x的格式
    InetAddress inetAddress = InetAddress.getByName(host); 
    String ip = inetAddress.getHostAddress();

    String blackSubnetlist[] = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}; //内网ip段
    for(String subnet : blackSubnetlist) {
      SubnetUtils subnetUtils = new SubnetUtils(subnet); //commons-net 3.6
      if(subnetUtils.getInfo().isInRange(ip)) {
        return true; //如果ip在内网段中，直接返回
      }
    }
    return false;
}
```

## 0x03 参考资料

[JAVA代码审计之XXE与SSRF](https://xz.aliyun.com/t/2761)

[谈一谈如何在Python开发中拒绝SSRF漏洞](https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html)

