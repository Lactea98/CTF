# # Flag 2

이 블로그은 외부와 단절되어 있다고 설명되어있다. 그래서 Remote File Inclusion 공격이 되지 않는다. 하지만 Local File Inclusion 공격은 먹힌다.

다음과 같은 요청으로 index 파일을 inlcude 해보았다.

![image](https://user-images.githubusercontent.com/38517436/64423444-8343fa00-d0e1-11e9-8705-23c16c1db1c6.png)

다음과 같이 index.php 파일은 include 되었지만 파일 사이즈로 인해 실패는 했다. 

위와 같은 요청으로 include $_GET['page'].".php"; 라는 코드로 내부에 있는 파일을 include 한다는 것을 알게 되었다.

---

Flag1에서 찾은 admin 페이지에 comments를 승인하는 부분을 이용해보자.

메인 페이지에서 comments에 <?php echo readfile("index.php"); ?> 라고 작성한 뒤 이를 승인해보자.

하지만 메인 페이지에는 위의 코드가 동작하지 않는다.

여기서 LFI 공격을 사용한다.

?page=http://localhost/index 라고 호출을 하면 index.php 파일 내부에 http://localhost/index.php 파일을 include 해서 php 코드를 실행한다. 

즉 아까 입력하고 승인해준 <?php echo readfile("index.php"); ?> 이 코드가 page 파라미터의 값인 http://localhost/index.php의 include로 인해 코드가 실행되게 된다. 

아래 사진 처럼 ?page=http://localhost/index.php 라고 요청을 보내면 index.php 소스코드를 유출 시킬 수 있게 된다.

![image](https://user-images.githubusercontent.com/38517436/64424254-8b049e00-d0e3-11e9-840d-506060601cec.png)
