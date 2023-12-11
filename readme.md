# WRITEUP SVATTT - ASCIS 2022

Sau gần tuần kết thúc kì thi SVATTT hôm nay mình mới ngồi viết wu được. 

Quả thực là lần đầu tiên mình đi thi off và tại KMA nữa, rất nhiều cảm xúc và cũng khá vui khi team cùi bắp của mình vẫn được giải KK.



Okay, làm việc thôi nào!!



## 1. [crypto+re] Classified information

![image-20221019235931847](./img/image-20221019235931847.png)

Đây được đánh giá là câu crypto khó nhất, vì nó kết hợp cả re :v. Và một thằng chơi re như mình cũng bối rối khi đánh giá quá thấp chall này. Và mình đã không giải được nó trong thời gian thi.



Đề chall cho một file exe (chắc cần re) , một pdf (chưa biết để làm gì) , config.bin (chưa biết là j, có thể là thư viện bên ngoài của exe ?) và một **secret.ascis** (mở ra thì thấy magicnum là ascis => đã bị mã hóa). Nên ta đoán ý tưởng chung là dịch ngược problem.exe và mô phỏng lại cách nó hoạt động (bằng py hoặc c,...) để giải mã **secret.ascis** lấy cờ. Mà dạng bài như thế này secret sẽ được viết ra có cấu trúc, nên mình nắm đc cấu trúc là viết lại được code giải mã.



### a. Re cái problem.exe



Không nhiều lời ta ném nó vào ida.

![image-20221019235829154](./img/image-20221019235829154.png)

Đọc đoạn đầu ta thấy config.bin được đọc vào, và đem xor với một số giá trị kì lạ 

Mình có đặt breakpoint trước khi nó thực hiện CreateObject và thấy rằng file config.bin là một file DLL và nó import vào các hàm mã hóa cho problem.exe



![image-20221020000102500](./img/image-20221020000102500.png)



Tiếp bên dưới có hai cái if điểm kiểm tra tham số, đây là hai hàm quan trọng nhất của chall này.

và có hai mode là a và x ta thêm vào tham số khi gọi hàm.

![image-20221020000235177](./img/image-20221020000235177.png)

Mình có test thử với file của mình để đoán các tham số truyền vào có thể là gì.

và **Với mode a** : problem thực hiện mã hóa các file ghi vào arg[2] (test.ascis) là tên file lưu những thứ nó đã mã hóa, và các tham số từ 4 trở đi là tên các file cần mã hóa(để chung thư mục với problem.exe). Tham số thứ 4 thì mình đoán là khóa nó dùng để mã hóa hoặc làm gì đó.

Với mode x : problem giải mã các file  từ test.ascis ra tham số thứ 4 vẫn phải là khóa đó mới giải được, tham số thứ 5 là output_folder (mình để là .)



-------------------------

Từ đây nắm được các luồng hd của problem rồi, mình phân tích tĩnh trên ida sẽ có định hướng hơn.

---------

- Hàm **ENC A**

![image-20221020000817224](./img/image-20221020000817224.png)

bên trên toàn là những hàm genrandom, mà random mình sẽ khó đoán đc nên mình bỏ qua.



![image-20221020000953641](./img/image-20221020000953641.png)



mình chú ý nhiều hơn ở đoạn mã hóa bên dưới này, vì nó có một cái flag giả cực chất  *"ASCIS{1t_i5_v3Ry_str0nG_p@S5w0Rd}"*

Nó được làm password hash cho thuật toán PBKDF2 với kiểu sha256.

Mình không làm được bài này cũng chính vì mình không biết đến thuật toán PBKDF2 cứ nghĩ nó là sha256 thông thường.

Hơn nữa mình còn thấy nó truyền vào cả salt, vậy là đoạn này không phải sha256 thông thường rồi.!

![image-20221020001303102](./img/image-20221020001303102.png)



mình cũng cần quan tâm một tham số nữa trong hàm trên, đó là iteration,.. nó là 20000



- tiếp tục re :...

Sau khi hash kết quả sẽ trả ra pbSecret

rồi nhảy tới hàm AES encrypt 

![image-20221020001443780](./img/image-20221020001443780.png)



và rất dễ nhận thấy đó là AES CBC => cần tìm IV nữa.





![image-20221020001605620](./img/image-20221020001605620.png)



xuống dịch dưới có hàm encrypt ...mình có thể tra ngược lên để xem iv cần truyền vào là gì ...



![image-20221020011158306](./img/image-20221020011158306.png)

Sau khi gọi xong hàm AES _ sub_7FF608F15EE0 để mã hóa nội dung các file , ta nhìn thấy được cái cấu trúc được ghi ra của gile .ascis . Đây là mấu chốt quan trọng để ta decrypt được file secret.ascis



fwrite("ASCIS", 1ui64, 8ui64, v17) == 8     mở đầu của file sẽ được ghi ra 8 bytes này. và chú ý là hàm fwrite trả ra size đã được viết.

Và tiếp tục đọc, 16 bytes tiếp theo được ghi ra là phBuffer (- chính là salt của thuật toán hash bên trên)

![image-20221020011608266](./img/image-20221020011608266.png)

 16 bytes tiếp là IV vừa dùng để AES CBC 

![image-20221020011713471](./img/image-20221020011713471.png)



> Đoạn tìm được cấu trúc file này thực sự mình lúc đầu đã làm bị sai hướng tiếp cận dịch ngược
>
> Mình lại tìm cách đọc cấu trúc từ hàm decrypt (tập trung ở hàm decrypt nhiều hơn và hy vọng có thể dùng decrypt của nó để giải mã được ngay). 
>
> Và kết quả là khi chương trình đọc lại file theo cấu trúc để lấy salt iv lại thì hàm viết rất rối và mình bế tắc luôn 
>
> ![image-20221020012131803](./img/image-20221020012131803.png)

=> Bài học xương máu : Tìm cấu trúc file bị encrypt -> tìm ở hàm encrypt





Quay ngược về phía trên một chút,  mình thấy được trước khi thực hiện mã hóa AES CBC nó còn dùng một hàm để tạo một file zip

![image-20221020012252834](./img/image-20221020012252834.png)

 sub_7FF608F17980([ten file ascis], [mật khẩu], [..., danh sách tên cách file sẽ encrypt])

Vậy là tất cả các file sẽ được tạo thành một file zip rồi đặt password sau đó mới đem đi mã hóa.

Còn tại sao mình biết nó là hàm để tạo zip. Thì đó là mình copy tên một số hàm như (&CArchiveUpdateCallback::`vftable';, ) tìm trên google và đoán thôi :))

![image-20221020012721243](./img/image-20221020012721243.png)



- Hàm Dec X cũng tương tự các thành phần như vậy nhưng được thực hiện ngược lại nên mình không trình bày ra nữa.

> Ý tưởng để làm bây giờ là : Giải AES CBC của secret.ascis để lấy ra được file zip là thành công.



### b. Code giải mã secret.ascis

Hiểu ý tưởng rồi bắt tay vào code cũng đầy gian nan đối với minh.

Mình sẽ show code và nói luôn cách giải quyết mà mình rút ra được.

![image-20221020013304239](./img/image-20221020013304239.png)



- Tại hàm Dec X mình đặt breakpoint như sau :

![image-20221020013336913](./img/image-20221020013336913.png)

Cùng với thiết lần để debug

![image-20221020013355823](./img/image-20221020013355823.png)

- Mục đích chính là mượn tool của nó để tạo ra hash key cho aes :))

![image-20221020013506651](./img/image-20221020013506651.png)

hashkey sẽ trả về biến phSecret .

![image-20221020013717459](./img/image-20221020013717459.png)

và nó nằm đây :)) b chon edit > export data để lấy data ra nhé !

- Và mình chạy python solve.py thôi

![image-20221020013837367](./img/image-20221020013837367.png)



thấy được là hai bytes đầu là PK - magicnum của file zip . Vậy là đúng rồi đó !!



> Bài học xương máu : Mình và Trung đã mất nhiều thời gian để cố tìm thư viện để tạo lại thuật toán hash pbkdf2
>
> nhưng thật sự pbkdf2 có thể đã bị chỉnh sửa và mình cần thực hiện phương pháp tận dụng-chặn bắt 
>
> để tạo hash key một cách nhanh chóng, chính xác ngay lập tức

![image-20221020014400704](./img/image-20221020014400704.png)

*nhớ sửa lại phần mở rộng của file dump nhé!!*



> Update : Cách code dùng thư viện và không cần debug để lấy key hash
>
> :)) sau khi được tiền bối chỉ ra mình dùng thư viện ngu mình đã sửa lại code để decrypt file secret.ascis
>
> ![image-20221020161313937](./img/image-20221020161313937.png)
>
> 



### c. File zip có pass ? Crack pass sao đây ?

![image-20221020014437741](./img/image-20221020014437741.png)

Một vấn đề nữa được đặt ra khi mình đã có file zip. Đó là file còn được đặt pass ạ.

Thực ra vấn đề này mình đã được các bạn của đội duy nhất làm được câu này trong thời gian thi gợi ý.

Nên việc giải quyết cũng không khó khăn lắm.

Điểm yếu để crack ở đây là ZipCrypto có thể tính toán được Keys khi biết một số plaintext nhất định.

Các bạn đọc thêm ở đây: https://webdevolutions.blob.core.windows.net/blog/pdf/why-you-should-never-use-zipcrypto.pdf



Và mình dùng tool : https://github.com/kimci86/bkcrack để crack key file zip

![image-20221020014758060](./img/image-20221020014758060.png)

![image-20221020015002726](./img/image-20221020015002726.png)

okay dưới đây là thao tác mình làm 

![image-20221020014821407](./img/image-20221020014821407.png)

Bạn cần lên mạng tìm và tải file này để làm một plaintext . Sau đó sửa tên giống file trong file zip nhé !.

![image-20221020014902348](./img/image-20221020014902348.png)



![image-20221020015040367](./img/image-20221020015040367.png)



![image-20221020014837927](./img/image-20221020014837927.png)



Sau đó dùng câu lệnh trên để đổi pass file zip về một pass theo ý bạn. 

![image-20221020015146036](./img/image-20221020015146036.png)

Và thành quả thực sự xứng đáng cho sự cố gắng muộn màng. Kaka



> Bài này thật sự rất hay. 







