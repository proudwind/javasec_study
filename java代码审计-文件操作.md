# java代码审计-文件操作

## 0x01 文件上传

这段代码来自菜鸟教程：

```java
private static final String UPLOAD_PATH = "/tmp/upload";
private boolean uploadWithFileUpload(HttpServletRequest request) {
  if(!ServletFileUpload.isMultipartContent(request)) {
    //response.getWriter().print("Error: 表单必须包含 enctype=multipart/form-data");
    return false;
  }
	/*省略部分初始化代码*/
  try {
    List<FileItem> fileItems = servletFileUpload.parseRequest(request);
    if(fileItems != null && fileItems.size() > 0) {
      for(FileItem fileItem : fileItems) {
        String fileName = new File(fileItem.getName()).getName(); //获取文件名
        String filePath = UPLOAD_PATH + File.separator + fileName; //上传路径
        File storeFile = new File(filePath);
        fileItem.write(storeFile); //写文件
      }
      //response.getWriter().println("upload success");
    }
  } catch (Exception e) {
    //response.getWriter().print(e.getMessage());
    return false;
  }
  return true;
}
```

标准的任意文件上传代码。。。现在的web框架会将上传的文件放在web访问不到的位置存储，这样会一定程度上缓解上传漏洞，但如果在展示文件时处理不当，就会导致任意文件读取或下载。

servlet3之后，可以不使用commons-fileupload、commons-io这两个jar包来处理文件上传，转而使用`request.getParts()`获取上传文件。此外，servlet3还支持以注解的形式定义一些上传的属性。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190318224808.png)

```java
private boolean uploadWithAnnotation(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    Part part = request.getPart("fileName");
    if(part == null) {
      return false;
    }
    String filename = UPLOAD_PATH + File.separator + part.getSubmittedFileName();
    part.write(filename);
    part.delete();
    return true;
}
```

可以看到这种方法代码比较简洁，需要注意的是要在类前面加`@MultipartConfig`这个注解，否则会报错。

### 防御

文件上传参考这个[https://mp.weixin.qq.com/s/LzVseWzLP3CjQsmYzvELZA](<https://mp.weixin.qq.com/s/LzVseWzLP3CjQsmYzvELZA>)

1. 判断文件content-type

2. 文件上传后改名

   ```java
   String fileExt = filename.substring(filename.lastIndexOf(".") + 1); //获取后缀名
   String savename = UPLOAD_PATH + File.separator + DigestUtils.md5Hex(System.currentTimeMillis() + filename) + "." + fileExt;
   ```

3. 设置严格的后缀名白名单

   使用esapi的后缀名检测，需要在对应的resource目录建立`ESAPI.properties`和`validation.properties`，文件内容可以留空，也可以下载官方内容[https://github.com/ESAPI/esapi-java-legacy/blob/develop/src/test/resources/esapi](https://github.com/ESAPI/esapi-java-legacy/blob/develop/src/test/resources/esapi)

   ```java
   //检测后缀名
   if(!ESAPI.validator().isValidFileName("upload", filename, ALLOW_EXT, false)) {
       response.getWriter().println("后缀名不合法");
   }
   ```

4. 对文件大小进行限制

   基于`ServletFileUpload`

   ```java
   DiskFileItemFactory factory = new DiskFileItemFactory();
   ServletFileUpload servletFileUpload = new ServletFileUpload(factory);
   servletFileUpload.setSizeMax(1024 * 400);
   ```

   基于注解（ version > servlet3）

   ```java
   @MultipartConfig(maxFileSize = 1000 * 1024 * 1024, maxRequestSize = 1000 * 1024 * 1024)
   public class UploadServlet extends HttpServlet {}
   ```

5. 条件允许的情况下，将文件放到web访问不到的位置存储

## 0x02 文件操作（下载/读取/删除）

这几个操作比较类似，都是对文件的操作。

java的文件读取一般有两种方法，一种是基于InputStream，另一种是基于FileReader。

### 读取

```java
//InputStream
File file = new File(filename);
InputStream inputStream = new FileInputStream(file);
while(-1 != (len = inputStream.read())) {
  	outputStream.write(len);
}
```

```java
//FileReader
String fileContent = "";
FileReader fileReader = new FileReader(filename);
BufferedReader bufferedReader = new BufferedReader(fileReader);
String line = "";
while (null != (line = bufferedReader.readLine())) {
		fileContent += (line + "\n");
}
```

### 下载

读写操作都有的情况下，用流比较方便。

```java
//stream
String filename = request.getParameter("filename");
File file = new File(filename);

response.reset();
response.addHeader("Content-Disposition", "attachment;filename=" + new String(filename.getBytes("utf-8")));
response.addHeader("Content-Length", "" + file.length());
response.setContentType("application/octet-stream; charset=utf-8");

InputStream inputStream = new FileInputStream(file);
OutputStream outputStream = new BufferedOutputStream(response.getOutputStream());
int len;
while(-1 != (len = inputStream.read())) {
  outputStream.write(len);
}

inputStream.close();
outputStream.close();
```

### 删除

```java
String filename = request.getParameter("filename");
File file = new File(filename);
if(file != null && file.exists() && file.delete()) {
  	response.getWriter().println("delete success");
} else {
  	response.getWriter().println("delete failed");
}
```

### 防御

防御的核心在于对传入的文件名进行正确的过滤，防止跨目录。

```java
private boolean checkFilename(String filename) {
    filename = filename.replace("\\", "/"); //消除平台差异
  	//将文件操作限定在指定目录中
  	File file = new File(filename);
    if(file == null || !file.exists() || file.getCanonicalFile().getParent().equals(new File(DOWNLOAD_PATH).getCanonicalPath())) { //检测上级目录是否为指定目录
      return false;
    }
  	//检测文件名中是否有敏感字符
    List<String> blackList = Arrays.asList("./", "../");
    for(String badChar : blackList) {
      if(filename.contains(badChar)) {
        return false;
      }
    }
  	//对文件后缀名设置白名单
    List<String> whiteExt = Arrays.asList("png", "jpg", "gif", "jpeg", "doc");
    String fileExt = filename.substring(filename.lastIndexOf(".") + 1).toLowerCase();
    if(!whiteExt.contains(fileExt)) {
      return false;
    }
    return true;
}
```

## 0x03 文件写入

```java
//FileWriter
FileWriter fileWriter = new FileWriter(filename);
BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
bufferedWriter.write(fileContent);
bufferedWriter.close();
```

### 防御

文件写入与上述三个操作略有不同，在防御时需要对写入的内容进行过滤。

```java
private boolean checkFilecontent(String fileContent) {
    List<String> blackContents = Arrays.asList("<%@page", "<%!");
    for(String blackContent : blackContents) {
      if(fileContent.contains(blackContent)) {
        return false;
      }
    }
    return true;
}
```

在写入时最好将标签进行htmlencode

```java
String fileContent = request.getParameter("content");
fileContent = ESAPI.encoder().encodeForHTML(fileContent);
```

