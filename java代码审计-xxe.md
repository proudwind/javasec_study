# java代码审计-xxe

## 0x00 漏洞挖掘

java解析xml的方法有多种，比较常见的有四种：DOM、DOM4J、JDOM 和SAX。

```java
//1. DocumentBuilder 原生、可回显
import javax.xml.parsers.DocumentBuilderFactory;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
StringReader sr = new StringReader(xml_con);
InputSource is = new InputSource(sr);
Document document = db.parse(is); 

//2. saxReader 第三方库
import org.dom4j.io.SAXReader;
SAXReader saxReader = new SAXReader();
Document document = saxReader.read(request.getInputStream());

//3. SAXBuilder 第三方库
import org.jdom2.input.SAXBuilder;
SAXBuilder builder = new SAXBuilder();  
Document document = builder.build(request.getInputStream());

//4. SAXParserFactory 原生、不可回显
import javax.xml.parsers.SAXParserFactory;
SAXParserFactory factory  = SAXParserFactory.newInstance(); 
SAXParser saxparser = factory.newSAXParser();
SAXHandler handler = new SAXHandler();  
saxparser.parse(request.getInputStream(), handler);
```

还有其他整理如下：

```java
import org.xml.sax.helpers.XMLReaderFactory;
XMLReader xmlReader = XMLReaderFactory.createXMLReader();
xmlReader.parse( new InputSource(new StringReader(xml_con)) );

import org.apache.commons.digester3.Digester;
Digester digester = new Digester();
digester.parse(new StringReader(xml_con)); 

import javax.xml.parsers.DocumentBuilderFactory;
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setXIncludeAware(true);   // 支持XInclude
dbf.setNamespaceAware(true);  // 支持XInclude
DocumentBuilder db = dbf.newDocumentBuilder();
StringReader sr = new StringReader(xml_con);
InputSource is = new InputSource(sr);
Document document = db.parse(is);  // parse xml

SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser saxParser = spf.newSAXParser();
XMLReader xmlReader = saxParser.getXMLReader();
xmlReader.parse( new InputSource(new StringReader(xml_con)) );
```

通常parse方法返回void的，就是无回显的。

## 0x01 漏洞防御

xxe的防御比较简单，禁用外部实体即可。

```java
//实例化解析类之后通常会支持着三个配置
obj.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
obj.setFeature("http://xml.org/sax/features/external-general-entities", false);
obj.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

## 0x02 参考链接

[JAVA代码审计之XXE与SSRF](https://xz.aliyun.com/t/2761)

[https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/XXE.java](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/XXE.java)

