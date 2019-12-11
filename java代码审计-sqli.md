## Java代码审计-sqli

### 0x01 漏洞挖掘

#### jdbc

在上古时期，人们往往这么从数据库获取数据。

```java
public User getUserById(String id) throws SQLException {
    Connection connection = JDBCTOOLS.getConnection();
		String sql = "select id,username from user where id=" + id;
		Statement statement = connection.createStatement();
    ResultSet resultSet = statement.executeQuery(sql);

    resultSet.next();
    int userId = resultSet.getInt(1);
    String username = resultSet.getString(2);
    User user = new User(userId, username);
    return user;
}
```

通过拼接字符串来构建sql语句，其中又有用户可控的部分，很容易出现问题。

后来，出现了预编译机制，但是预编译只能处理查询参数，很多场景下仅仅使用预编译是不够的。

* like

  在使用模糊查询的场景中，

  ```java
  String sql = "select * from user where username like '%?%'";
  ```

  这种写法是无法进行预编译的，程序会报错。

* order by

  需要按照时间、id等信息进行排序的时候，也是无法使用预编译的。

  ```java
  String sort = req.getParameter("sort");
  
  String sql = "select * from user order by ?";
  PreparedStatement preparedStatement = connection.prepareStatement(sql); //预编译
  preparedStatement.setString(1, sort); //绑定参数
  ResultSet resultSet = preparedStatement.executeQuery();
  ```

  如果像上面这样强行使用预编译，数据库会将字段名解析为字符串，即实际执行的sql为

  ```sql
  select * from user order by 'username';
  ```

  无法达到实际需求。

#### Hibernate

```java
@Autowired CategoryDAO categoryDAO; //依赖注入

@RequestMapping("/hibernate")
public String hibernate(@RequestParam(name = "id") int id) {
  Category category = categoryDAO.getOne(id);
  return category.getName();
}
```

hibernate即我们经常使用的orm的一种实现，如果使用已封装好的方法，那么默认是使用预编译的。需要注意的有这么几种情况：

1. 对于一些复杂的sql语句，需要开发手写sql，此时要严格过滤用户输入。
2. 上面提到的预编译不生效的几种场景。

#### Mybatis

mybatis有两种写法，一种是基于注解：

```java
@Mapper
public interface CategoryMapper {
    @Select("select * from category_ where name= '${name}' ")
    public CategoryM getByName(@Param("name") String name);
}
```

另一种是基于xml：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="cn.seaii.springboot.mapper.CategoryMapper">
    <select id="get" resultType="cn.seaii.springboot.pojo.CategoryM">
        select * from category_ where id= ${id}
    </select>
</mapper>
```

注意在maven项目中，xml文件要放在resources目录中。

### 0x02 漏洞防御

#### 2.1 类型转换

java是一门强类型的语言，所以数字型注入一般很少出现，但还是要有必要的类型转换。

比如通过HttpServletRequest的getParameter方法获取到的参数的类型都是String。

```java
int id = Integer.valueof(req.getParameter("id"));
```

#### 2.2 预编译

无论那种web编程语言，目前防注入最通用、最流行的方法就是使用预编译。

```java
public User getUserById(String id) throws SQLException {
    Connection connection = JDBCTOOLS.getConnection(); //获取连接，细节省略
    String sql = "select id,username from user where id=?";
    PreparedStatement preparedStatement = connection.prepareStatement(sql); //预编译
    preparedStatement.setString(1, id); //绑定参数
    ResultSet resultSet = preparedStatement.executeQuery();

    resultSet.next();
    int userId = resultSet.getInt(1);
    String username = resultSet.getString(2);
    User user = new User(userId, username);
    return user;
}
```

在使用预编译之后，即使用户提交的参数中含有敏感关键字（union、select等），数据库也会将其作为对应字段的值来处理而不会解析其中的sql关键字。

mybatis中这样写：

```java
@Mapper
public interface CategoryMapper {
    @Select("select * from category_ where name= #{name} ")
    public CategoryM getByName(String name);
}
```

看起来比不使用预编译还要简单一点。

#### 2.3 其他防御

上面也提到过，预编译只能处理查询参数，对于其他位置存在用户可控的情况（order by、in、like等），无法提供有效的保护，此时就要具体情况具体分析。

以上面提到的两种情况为例：

```java
//like
String sql = "select * from user where username like concat('%', ?, '%')";
//预编译
```

order by可以设置白名单，只有白名单中的字段才可以拼接。

```java
private String checkSort(String sortBy) {
    List<String> columns = new ArrayList<>(Arrays.asList("id", "username"));
    return (columns.contains(sortBy)) ? sortBy : "''";
}
```

### 0x03 参考资料

[Mybatis框架下SQL注入漏洞面面观](https://mp.weixin.qq.com/s?__biz=MjM5OTk2MTMxOQ==&mid=2727827368&idx=1&sn=765d0835f0069b5145523c31e8229850&mpshare=1&scene=1&srcid=0926a6QC3pGbQ3Pznszb4n2q)

