# # Flag 

주석처리 되어 있는 ?page=admin.auth.inc 페이지에 접속을 했더니 아래와 같은 admin 페이지가 나왔다.

![image](https://user-images.githubusercontent.com/38517436/64422870-0bc19b00-d0e0-11e9-9637-8730f92b28fa.png)

그런데 여기서 ?page 라는 파라미터 변수가 file include 취약점이 있을거 같아 index 라고 적어서 요청을 보냈다.

![image](https://user-images.githubusercontent.com/38517436/64422988-58a57180-d0e0-11e9-8a0d-b8354a5d0aed.png)

위와 같이 index.php 파일이 include 된 것은 맞으나 파일 사이즈 때문에 호출 되지는 못했다.

혹시나 admin.auth.php 파일이나 admin.inc.php 파일이 있는지 ?page= 파라미터에 요청을 보냈더니 후자의 요청에 정상적인 응답이 왔다.

![image](https://user-images.githubusercontent.com/38517436/64423223-f1d48800-d0e0-11e9-9e6a-4acaf2c63748.png)
