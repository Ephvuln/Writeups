# Challenge
```
To use her e-mail, Alice needs to connect to a mail server. The authentication is unilateral, and works as follows:
1. Alice requests access to the server by sending her username.
2. The server randomly selects 2 values index1 and index2 (1 <= index1 < index2 <= 64), and challenges Alice with (index1, index2).
3. Alice applies SHA256 to her password, keeps the hex characters placed on the positions index1 and index2 unchanged and changes all the other hex characters to a different value. Then, she sends the result to the server.
4. The server receives the response, and checks if the received string equals the SHA256 value stored in the database for Alice’s username in exactly two positions: index1 and index2.
5. To decrease the chances to obtain access by luck, the server repeats the procedure and sends several requests to Alice before allowing her to access the e-mail. If Alice replies correctly to all challenges, then she is successfully authenticated; if not, Alice is denied access.
For example:
• SHA256(password) = aad3eda32ce777fa1cb3ca97ac7e1bfdd726053e05e0109b3526a63fed4519b7
• index1 = 5 and index2 = 60
• Valid reply (only hex characters on positions 5 and 60 are unchanged):
4c77ef3010c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9ddx475bffe
• Invalid reply (hex characters on positions 9 and 57 are also the same):
4c77ef3020c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9dde475bffe
• Invalid reply (hex character on position 5 is different):
4c77ff3010c2f5c274ebbb0ff5abe001eeb5ce0f944dd1402caaf9ddx475bffe
An adversary masquerades the server, and fools Alice to reply to his challenges. You are not given access to the challenges, but you know that the adversary only queried positions from the first half of the hash. You also have all the replies from Alice in Alice_replies.txt, and you know that the adversary found the complete hash. This hash is your flag.
```
Alice_replies.txt:
```
f14fd2705fa37ce36ab73472883cf329917c50eb06d2080f863fd6bf712377b1
ad3b393e6426aef4db1a49180797393a3cb6a7516d1b5f69a3d36138d9be121c
73c370746eb072da5deb8ce13febaa16d33dc714c24a8424018a8a16f46cbdcf
05bac2205f124251c03863a608322b5486c2ba8c1fe0fbaccb1942ed838deb30
312f3b3ef4ce5ef837b1c9837ba8f9ba6f6f21f73eff19ea39e105a1604c61fe
983bd1838b16b697c90731e7602c1a1ce44f4c62032a32f2dfaa50f638f14925
7ec14b2e54a24a7150f121468b5dabb47dd3eb0fbb13ea33b8f7dc171d9fc8ed
313f4b83fbbe56da3a34c0e13fa2e55cf5e5592344c4297b122899629e5290d3
98b1c1348423aa782838204775281aff2e5432782539d3832aa2142b0ca92a34
dc2bc85fa5302c51e919bb59d6eb27dc2a0004b9d867b7505e6528435a16a58a
fe0e584025c1816621aa3c745971c9d9c299733e897d51d6f54cb79ac3770f08
7561b7a5a2348c8bed05b7c9f6e4332718188dc8e0919d1e90bdced42be58476
adc3d4612bd6215627a94b58579ba789003a6faa97566c257d56fdc9a2603290
012f795543d1be84f81584c23b3123365187d52d7abe46cd44c073558534fe62
734ac4a39ee5bc9b6d044c19d9e7c386b7a198d6f188ce48ef04ed0e47d8f35b
3563504f92d40f67f1f8c7a4f57437274b2b1690ad0570b11c9b3f80e6cb5ca7
```
# Crack
## Method: cryptanalisis

We break the algorithm in 2 parts: one that solves the first half and the other that solves the
second. We keep in mind that the attacker found the hash with the minimum number of attempts
and had 16 attempts.

The first half’s key is composed of the only character found once in all the hashes ( looked column
wise ).

The second’ half’s key is composed of the only character found in none of the hashes ( looked
column wise ).

The first half:
Since we are looking at the minimum, we need just once to hold the index for one position. Any
other duplicate would mean that is not found in the real string. In order to be able to recover the
hash even if we don’t know the challenges, we can only have one value unique column wise, that
will be from the real hash.

The second half:
Since no indexes have been used, the only way we can recover the hash is by having all other
values ( but the real value ) on the columns, that just happens to be.

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int hex2char(char c)
{
if(c>='0'&& c<='9') return (c-'0');
else if(c>='a' && c<='f') return (c-'a'+10);
}char char2hex(int c)
{
if(c>=0&& c<=9) return (c+'0');
else if(c>=10 && c<=16) return (c+'a'-10);
}
char *solveMult(char half[16][33],int len)
{
char c[16][len+1],chr;
int i,j;
for(i=0;i<len;i++)
for(j=0;j<16;j++)c[j][i]=0;
for(i=0;i<len;i++)
for(j=0;j<16;j++)
c[hex2char(half[j][i])][i]++;
char *str=(char*)malloc(sizeof(char)*len+1);
int uniq, poz1, poz2,ok1, ok2;
for(i=0;i<len;i++)
{
ok2=1;
for(j=0;j<16;j++){
if(c[j][i]==1){
poz2=j;
}
}
str[i]=char2hex(poz2);
}
str[len]='\0';
return str;
}
char *solveUniq(char half[16][33],int len)
{
char c[16][len+1],chr;
int i,j;
for(i=0;i<len;i++)
for(j=0;j<16;j++)c[j][i]=0;
for(i=0;i<len;i++)
for(j=0;j<16;j++)
c[hex2char(half[j][i])][i]=1;
char *str=(char*)malloc(sizeof(char)*len+1);
for(i=0;i<len;i++)
for(j=0;j<16;j++){
if(c[j][i]==0){
str[i]=char2hex(j);
break;
}
}
str[len]='\0';
return str;
}
int main()
{
char half1[16][33]=
{"dc2bc85fa5302c51e919bb59d6eb27dc","983bd1838b16b697c90731e7602c1a1c","98b1c1348423aa782838204775281aff",
"012f795543d1be84f81584c23b312336","05bac2205f124251c03863a608322b54","f14fd2705fa37ce36ab73472883cf329",
"fe0e584025c1816621aa3c745971c9d9","7ec14b2e54a24a7150f121468b5dabb4","7561b7a5a2348c8bed05b7c9f6e43327",
"734ac4a39ee5bc9b6d044c19d9e7c386","73c370746eb072da5deb8ce13febaa16","3563504f92d40f67f1f8c7a4f5743727",
"312f3b3ef4ce5ef837b1c9837ba8f9ba","313f4b83fbbe56da3a34c0e13fa2e55c","ad3b393e6426aef4db1a49180797393a",
"adc3d4612bd6215627a94b58579ba789"};char half2[16][33]=
{"2a0004b9d867b7505e6528435a16a58a","e44f4c62032a32f2dfaa50f638f14925","2e5432782539d3832aa2142b0ca92a34",
"5187d52d7abe46cd44c073558534fe62","86c2ba8c1fe0fbaccb1942ed838deb30","917c50eb06d2080f863fd6bf712377b1",
"c299733e897d51d6f54cb79ac3770f08","7dd3eb0fbb13ea33b8f7dc171d9fc8ed","18188dc8e0919d1e90bdced42be58476",
"b7a198d6f188ce48ef04ed0e47d8f35b","d33dc714c24a8424018a8a16f46cbdcf","4b2b1690ad0570b11c9b3f80e6cb5ca7",
"6f6f21f73eff19ea39e105a1604c61fe","f5e5592344c4297b122899629e5290d3","3cb6a7516d1b5f69a3d36138d9be121c",
"003a6faa97566c257d56fdc9a2603290"};
char *half1solved=solveMult(half1,32), *half2solved=solveUniq(half2,32);
printf("%s%s",half1solved,half2solved);
free(half2solved);
free(half1solved);
}
```