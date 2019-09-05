# PHP-NOTE

### Intro

이번 문제는 TokyoWesterns CTF 2019에서 나온 web 문제 "php note" 이다.

문제 사이트 링크는 다음과 같다. [http://phpnote.chal.ctf.westerns.tokyo](http://phpnote.chal.ctf.westerns.tokyo)

이 문제의 소스코드를 보기 위해서는 ?page=source 라고 요청을 보내면 php source 를 볼 수 있다.

이 문제의 기능을 간단히 설명하자면, 사용자가 입력한 note를 SESSION에 직렬화하여 저장하고, 작성한 글을 불러 올때는 SESSION에 있는 직렬화된 데이터를 역직렬화하여 웹 페이지에 출력한다.


### Guess

이 문제의 소스코드를 봤을 때 처음 생각이 난 부분은 php serialization vulnerability와 [https://univ-blog.xyz/entry/web-Deadly-bug-code-php](https://univ-blog.xyz/entry/web-Deadly-bug-code-php) 여기에 나와있는 코드와 매우 유사한 부분인 점이다.

php serialization 부분을 찾아봤지만 이번 문제에서는 이용할 만한 취약점은 아니었다. 위 링크에 나와있는 코드와 문제의 일부분 코드가 유사해서 똑같은 방법으로 hash_hmac()에 array를 집어 넣어도 문제를 풀 만한 방향은 아니었다.

그래서 포기...가 아니라 잠시 wrtieup이 올라 올때 까지 존버를 했다.

[https://saarsec.rocks/2019/09/04/twctf-phpnote.html](https://saarsec.rocks/2019/09/04/twctf-phpnote.html) 여기 링크에 php note의 writeup이 올라왔다.!!! 

사지방으로 달려가 흥분을 가라앉히고 천천히 롸없을 봤다.ㅎㅎ

이 이후는 위 링크를 참고하여 작성한 wrire up 이다.

### Information of challenge "php note"

이 문제는 SECRET값과 realname, nickname을 SESSION 에 저장하고 관리한다. 따라서 만약 사용자가 이 사이트에 로그인을 하게 된다면 다음과 같이 SESSION 파일에 저장이 될것이다.

```
realname|s:11:"Hello World";nickname|s:6:"alfink";secret|s:32:"13371337133713371337133713371337";
```


이 문제는 windows 10 서버로 운영되고 있다. Response packet을 통해 알 수 있었다.
```
Response Header

Content-Length: 27171
Content-Type: text/html; charset=UTF-8
Date: Thu, 05 Sep 2019 04:53:10 GMT
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.9
```

기본적으로 windows 10은 Windows Defender가 깔려 있다. Windows Defender는 세션 파일을 포함한 모든 파일을 감시한다. 그래서 만약 세션 파일에 악의적인 스크립가 들어가 있다면, Windows Defender는 이 파일을 탐지하게 되고 로그인에 실패하게 된다. 

예를들어, realname에 ``` var miner = new CoinHive.User(); miner.start() ``` 라고 입력하고 가입을 하게 되면 어떻게 될까? 

Windows Defender 내장에는 javascript Engine이 있어 javascript 코드를 실행 할 수 있다고 한다. 따라서 위 javascript는 coin을 채굴하는 악성 스크립트로 판단하여 세션 파일을 탐지하고 로그인이 실패하게 된다. (실제로 login 입력 값을 악성 스크립트를 넘겼는데, 로그인이 안된다...미친..)

따라서 첫번째 스크립트를 포함해서 로그인을 시도하면 로그인이 되지 않고, 두번재는 그렇지 않았다.

```javascript
<script>
    var mal = 'var miner=new Coin';
    var n = document.body.innerHTML.charCodeAt(0);
    mal = mal + String.fromCharCode(n^40) + 'ive.User();miner.start';
    eval(mal);
</script>
```

```javascript
<script>
    var mal = 'var miner=new Coin';
    var n = document.body.innerHTML.charCodeAt(0);
    mal = mal + String.fromCharCode(n^65) + 'ive.User();miner.start';
    eval(mal);
</script>
```

위 코드를 이용해서 SESSION 값에 접근을 하여 SECRET 값을 유출 시킬 수 있다.


### Approach the SECRET using javascript

SESSION에 javascript를 삽입하여 SESSION에 들어있는 SECRET을 유출시켜 보자.

php note 문제의 소스코드 중 다음과 같은 SESSION에 realname과 nicname, secret을 저장하는 코드가 있다.

```php
if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];

        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }

        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
    }
    redirect('index');
}

```

위 코드의 흐름을 간단히 설명하자면 nickname 값이 없다면 realname, secret 순으로 저장이 된다.

**[nickname 값이 없을때]**

```
SESSION ==> realname|s:8:"universe";secret|s:32:"111111111111111111111111111111111111";
```

이 상태에서 nickname을 포함하여 다시 요청을 보내면 realname과 secret 값은 갱신이 되고 nickname은 SESSION 값의 맨 마지막에 추가가 된다.

**[nickname 값을 추가하여 다시 로그인 요청을 했을 때]**

```
SESSION ==> realname|s:8:"universe";secret|s:32:"111111111111111111111111111111111111";nickname|s:8:"universe";
```







