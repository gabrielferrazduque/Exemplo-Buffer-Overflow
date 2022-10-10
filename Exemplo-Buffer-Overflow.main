#include <stdio.h>
#include <string.h>

int main (void) {
  char buffer[5];
  printf("Digite seu nome>\n");
  scanf("%s", &buffer);
 strcpy() -> strncpy()
strcat() -> strncat()
strlen() -> strnlen()
strcmp() -> strncmp()
strdup() -> strndup()
wcscpy() -> wcsncpy()
wcslen() -> wcsnlen()
sprintf() -> snprintf() 
 scanf(), getwd(), realpath() atoi(), memcpy(), strtok(),  

 gets()
 

  return 0;
}
#include <stdio.h>
#include <string.h>

int main (void) {
  char buffer[5];
  printf("Digite seu nome>\n");
  scanf("%s", &buffer);
 strcpy() -> strncpy()
strcat() -> strncat()
strlen() -> strnlen()
strcmp() -> strncmp()
strdup() -> strndup()
wcscpy() -> wcsncpy()
wcslen() -> wcsnlen()
sprintf() -> snprintf() 
 scanf(), getwd(), realpath() atoi(), memcpy(), strtok(),  

 gets()
 

  return 0;
}
#include <cstdio>
#include <cstring>
#include <iostream>

const char *PASSWORD_FILE = "rictro";

int main()
{
  char input[8];
  char password[8];

  std::sscanf(PASSWORD_FILE, "%s", password);

  std::cout << "Enter password: ";
  std::cin >> input;

  // Debug prints:
  // std::cout << "Address of input: " << &input << "\n";
  // std::cout << "Address of password: " << &password << "\n";
  // std::cout << "Input: " << input << "\n";
  // std::cout << "Password: " << password << "\n";

  if (std::strncmp(password, input, 8) == 0)
    std::cout << "Access granted\n";
  else
    std::cout << "Access denied\n";

  return 0;
}
#include <cstdio>
#include <cstring>
#include <iostream>

const char *PASSWORD_FILE = "rictro";

int main()
{
  char input[8];
  char password[8];

  std::sscanf(PASSWORD_FILE, "%s", password);

  std::cout << "Enter password: ";
  std::cin >> input;

  // Debug prints:
  // std::cout << "Address of input: " << &input << "\n";include <string>
#include <iostream>

using namespace std; 

int main()
{
  begin:
  int authentication = 0;
  char cUsername[10], cPassword[10];
  char cUser[10], cPass[10];

  cout << "Username: ";
  cin >> cUser;

  cout << "Pass: ";
  cin >> cPass;

  strcpy(cUsername, cUser);
  strcpy(cPassword, cPass);

  if(strcmp(cUsername, "admin") == 0 && strcmp(cPassword, "adminpass") == 0)
  {
    authentication = 1;
  }
  if(authentication)
  {
    cout << "Access granted\n";
    cout << (char)authentication;
  } 
  else 
  {
    cout << "Wrong username and password\n";
  }

  system("pause");
  goto begin;
}
 #include <iostream>

int main( void )
{
 int authentication = 0;
 char cUsername[ 10 ];
 char cPassword[ 10 ];

 std::cout << "Username: ";
 std::cin >> cUsername;

 std::cout << "Pass: ";
 std::cin >> cPassword;

 if( std::strcmp( cUsername, "admin" ) == 0 && std::strcmp( cPassword, "adminpass" ) == 0 )
 {
  authentication = 1;
 }
 if( authentication )
 {
  std::cout << "Access granted\n";
  std::cout << ( char )authentication;
 }
 else
 {
  std::cout << "Wrong username and password\n";
 }

 return ( 0 ); 


  00000001`3f1f1710 4883ec68        sub     rsp,68h
00000001`3f1f1714 488b0515db0300  mov     rax,qword ptr [Prototype_Console!__security_cookie (00000001`3f22f230)]
00000001`3f1f171b 4833c4          xor     rax,rsp
00000001`3f1f171e 4889442450      mov     qword ptr [rsp+50h],rax
00000001`3f1f1723 c744243800000000 mov     dword ptr [rsp+38h],0  // This gives us address of "authentication" on stack.
00000001`3f1f172b 488d156e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x78 (00000001`3f2233a0)]
00000001`3f1f1732 488d0d47f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f1739 e8fdf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f173e 488d542428      lea     rdx,[rsp+28h] // This gives us address of "cUsername" on stack.
00000001`3f1f1743 488d0df6f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f174a e823faffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f174f 488d153e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x6c (00000001`3f223394)]
00000001`3f1f1756 488d0d23f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f175d e8d9f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f1762 488d542440      lea     rdx,[rsp+40h] // This gives us address of "cPassword" on stack.
00000001`3f1f1767 488d0dd2f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f176e e8fff9ffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f1773 488d15321c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x84 (00000001`3f2233ac)]
00000001`3f1f177a 488d4c2428      lea     rcx,[rsp+28h]
00000001`3f1f177f e86c420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1784 85c0            test    eax,eax
00000001`3f1f1786 751d            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f1788 488d15291c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x90 (00000001`3f2233b8)]
00000001`3f1f178f 488d4c2440      lea     rcx,[rsp+40h]
00000001`3f1f1794 e857420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1799 85c0            test    eax,eax
00000001`3f1f179b 7508            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f179d c744243801000000 mov     dword ptr [rsp+38h],1
00000001`3f1f17a5 837c243800      cmp     dword ptr [rsp+38h],0
00000001`3f1f17aa 7426            je      Prototype_Console!main+0xc2 (00000001`3f1f17d2)
00000001`3f1f17ac 488d15151c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xa0 (00000001`3f2233c8)]
00000001`3f1f17b3 488d0dc6ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17ba e87cf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17bf 0fb6542438      movzx   edx,byte ptr [rsp+38h]
00000001`3f1f17c4 488d0db5ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17cb e825f9ffff      call    Prototype_Console!ILT+240(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f10f5)
00000001`3f1f17d0 eb13            jmp     Prototype_Console!main+0xd5 (00000001`3f1f17e5)
00000001`3f1f17d2 488d15ff1b0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xb0 (00000001`3f2233d8)]
00000001`3f1f17d9 488d0da0ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17e0 e856f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17e5 33c0            xor     eax,eax
00000001`3f1f17e7 488b4c2450      mov     rcx,qword ptr [rsp+50h]
00000001`3f1f17ec 4833cc          xor     rcx,rsp
00000001`3f1f17ef e8bc420000      call    Prototype_Console!__security_check_cookie (00000001`3f1f5ab0)
00000001`3f1f17f4 4883c468        add     rsp,68h
00000001`3f1f17f8 c3              ret
 
 -----> old RSP value // Stack frame of caller of `main` is above, stack frame of main is below 

      16 bytes of
      "cPassword"
+40h
     8 bytes of "authentication"
+38h
      16 bytes of
      "cUsername"
+28h   


-----> RSP value = old RSP-68h
 
 Username:cPassword
Pass: whatever
Access granted
1

include <string>
#include <iostream>

using namespace std; 

int main()
{
  begin:
  int authentication = 0;
  char cUsername[10], cPassword[10];
  char cUser[10], cPass[10];

  cout << "Username: ";
  cin >> cUser;

  cout << "Pass: ";
  cin >> cPass;

  strcpy(cUsername, cUser);
  strcpy(cPassword, cPass);

  if(strcmp(cUsername, "admin") == 0 && strcmp(cPassword, "adminpass") == 0)
  {
    authentication = 1;
  }
  if(authentication)
  {
    cout << "Access granted\n";
    cout << (char)authentication;
  } 
  else 
  {
    cout << "Wrong username and password\n";
  }

  system("pause");
  goto begin;
}
 #include <iostream>

int main( void )
{
 int authentication = 0;
 char cUsername[ 10 ];
 char cPassword[ 10 ];

 std::cout << "Username: ";
 std::cin >> cUsername;

 std::cout << "Pass: ";
 std::cin >> cPassword;

 if( std::strcmp( cUsername, "admin" ) == 0 && std::strcmp( cPassword, "adminpass" ) == 0 )
 {
  authentication = 1;
 }
 if( authentication )
 {
  std::cout << "Access granted\n";
  std::cout << ( char )authentication;
 }
 else
 {
  std::cout << "Wrong username and password\n";
 }

 return ( 0 ); 


  00000001`3f1f1710 4883ec68        sub     rsp,68h
00000001`3f1f1714 488b0515db0300  mov     rax,qword ptr [Prototype_Console!__security_cookie (00000001`3f22f230)]
00000001`3f1f171b 4833c4          xor     rax,rsp
00000001`3f1f171e 4889442450      mov     qword ptr [rsp+50h],rax
00000001`3f1f1723 c744243800000000 mov     dword ptr [rsp+38h],0  // This gives us address of "authentication" on stack.
00000001`3f1f172b 488d156e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x78 (00000001`3f2233a0)]
00000001`3f1f1732 488d0d47f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f1739 e8fdf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f173e 488d542428      lea     rdx,[rsp+28h] // This gives us address of "cUsername" on stack.
00000001`3f1f1743 488d0df6f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f174a e823faffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f174f 488d153e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x6c (00000001`3f223394)]
00000001`3f1f1756 488d0d23f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f175d e8d9f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f1762 488d542440      lea     rdx,[rsp+40h] // This gives us address of "cPassword" on stack.
00000001`3f1f1767 488d0dd2f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f176e e8fff9ffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f1773 488d15321c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x84 (00000001`3f2233ac)]
00000001`3f1f177a 488d4c2428      lea     rcx,[rsp+28h]
00000001`3f1f177f e86c420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1784 85c0            test    eax,eax
00000001`3f1f1786 751d            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f1788 488d15291c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x90 (00000001`3f2233b8)]
00000001`3f1f178f 488d4c2440      lea     rcx,[rsp+40h]
00000001`3f1f1794 e857420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1799 85c0            test    eax,eax
00000001`3f1f179b 7508            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f179d c744243801000000 mov     dword ptr [rsp+38h],1
00000001`3f1f17a5 837c243800      cmp     dword ptr [rsp+38h],0
00000001`3f1f17aa 7426            je      Prototype_Console!main+0xc2 (00000001`3f1f17d2)
00000001`3f1f17ac 488d15151c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xa0 (00000001`3f2233c8)]
00000001`3f1f17b3 488d0dc6ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17ba e87cf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17bf 0fb6542438      movzx   edx,byte ptr [rsp+38h]
00000001`3f1f17c4 488d0db5ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17cb e825f9ffff      call    Prototype_Console!ILT+240(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f10f5)
00000001`3f1f17d0 eb13            jmp     Prototype_Console!main+0xd5 (00000001`3f1f17e5)
00000001`3f1f17d2 488d15ff1b0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xb0 (00000001`3f2233d8)]
00000001`3f1f17d9 488d0da0ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17e0 e856f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17e5 33c0            xor     eax,eax
00000001`3f1f17e7 488b4c2450      mov     rcx,qword ptr [rsp+50h]
00000001`3f1f17ec 4833cc          xor     rcx,rsp
00000001`3f1f17ef e8bc420000      call    Prototype_Console!__security_check_cookie (00000001`3f1f5ab0)
00000001`3f1f17f4 4883c468        add     rsp,68h
00000001`3f1f17f8 c3              ret
 
 -----> old RSP value // Stack frame of caller of `main` is above, stack frame of main is below 

      16 bytes of
      "cPassword"
+40h
     8 bytes of "authentication"
+38h
      16 bytes of
      "cUsername"
+28h   


-----> RSP value = old RSP-68h
 
 Username:cPassword
Pass: whatever
Access granted
1
include <string>
#include <iostream>

using namespace std; 

int main()
{
  begin:
  int authentication = 0;
  char cUsername[10], cPassword[10];
  char cUser[10], cPass[10];

  cout << "Username: ";
  cin >> cUser;

  cout << "Pass: ";
  cin >> cPass;

  strcpy(cUsername, cUser);
  strcpy(cPassword, cPass);

  if(strcmp(cUsername, "admin") == 0 && strcmp(cPassword, "adminpass") == 0)
  {
    authentication = 1;
  }
  if(authentication)
  {
    cout << "Access granted\n";
    cout << (char)authentication;
  } 
  else 
  {
    cout << "Wrong username and password\n";
  }

  system("pause");
  goto begin;
}
 #include <iostream>

int main( void )
{
 int authentication = 0;
 char cUsername[ 10 ];
 char cPassword[ 10 ];

 std::cout << "Username: ";
 std::cin >> cUsername;

 std::cout << "Pass: ";
 std::cin >> cPassword;

 if( std::strcmp( cUsername, "admin" ) == 0 && std::strcmp( cPassword, "adminpass" ) == 0 )
 {
  authentication = 1;
 }
 if( authentication )
 {
  std::cout << "Access granted\n";
  std::cout << ( char )authentication;
 }
 else
 {
  std::cout << "Wrong username and password\n";
 }

 return ( 0 ); 


  00000001`3f1f1710 4883ec68        sub     rsp,68h
00000001`3f1f1714 488b0515db0300  mov     rax,qword ptr [Prototype_Console!__security_cookie (00000001`3f22f230)]
00000001`3f1f171b 4833c4          xor     rax,rsp
00000001`3f1f171e 4889442450      mov     qword ptr [rsp+50h],rax
00000001`3f1f1723 c744243800000000 mov     dword ptr [rsp+38h],0  // This gives us address of "authentication" on stack.
00000001`3f1f172b 488d156e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x78 (00000001`3f2233a0)]
00000001`3f1f1732 488d0d47f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f1739 e8fdf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f173e 488d542428      lea     rdx,[rsp+28h] // This gives us address of "cUsername" on stack.
00000001`3f1f1743 488d0df6f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f174a e823faffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f174f 488d153e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x6c (00000001`3f223394)]
00000001`3f1f1756 488d0d23f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f175d e8d9f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f1762 488d542440      lea     rdx,[rsp+40h] // This gives us address of "cPassword" on stack.
00000001`3f1f1767 488d0dd2f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f176e e8fff9ffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f1773 488d15321c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x84 (00000001`3f2233ac)]
00000001`3f1f177a 488d4c2428      lea     rcx,[rsp+28h]
00000001`3f1f177f e86c420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1784 85c0            test    eax,eax
00000001`3f1f1786 751d            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f1788 488d15291c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x90 (00000001`3f2233b8)]
00000001`3f1f178f 488d4c2440      lea     rcx,[rsp+40h]
00000001`3f1f1794 e857420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1799 85c0            test    eax,eax
00000001`3f1f179b 7508            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f179d c744243801000000 mov     dword ptr [rsp+38h],1
00000001`3f1f17a5 837c243800      cmp     dword ptr [rsp+38h],0
00000001`3f1f17aa 7426            je      Prototype_Console!main+0xc2 (00000001`3f1f17d2)
00000001`3f1f17ac 488d15151c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xa0 (00000001`3f2233c8)]
00000001`3f1f17b3 488d0dc6ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17ba e87cf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17bf 0fb6542438      movzx   edx,byte ptr [rsp+38h]
00000001`3f1f17c4 488d0db5ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17cb e825f9ffff      call    Prototype_Console!ILT+240(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f10f5)
00000001`3f1f17d0 eb13            jmp     Prototype_Console!main+0xd5 (00000001`3f1f17e5)
00000001`3f1f17d2 488d15ff1b0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xb0 (00000001`3f2233d8)]
00000001`3f1f17d9 488d0da0ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17e0 e856f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17e5 33c0            xor     eax,eax
00000001`3f1f17e7 488b4c2450      mov     rcx,qword ptr [rsp+50h]
00000001`3f1f17ec 4833cc          xor     rcx,rsp
00000001`3f1f17ef e8bc420000      call    Prototype_Console!__security_check_cookie (00000001`3f1f5ab0)
00000001`3f1f17f4 4883c468        add     rsp,68h
00000001`3f1f17f8 c3              ret
 
 -----> old RSP value // Stack frame of caller of `main` is above, stack frame of main is below 

      16 bytes of
      "cPassword"
+40h
     8 bytes of "authentication"
+38h
      16 bytes of
      "cUsername"
+28h   


-----> RSP value = old RSP-68h
 
 Username:cPassword
Pass: whatever
Access granted
1

include <string>
#include <iostream>

using namespace std; 

int main()
{
  begin:
  int authentication = 0;
  char cUsername[10], cPassword[10];
  char cUser[10], cPass[10];

  cout << "Username: ";
  cin >> cUser;

  cout << "Pass: ";
  cin >> cPass;

  strcpy(cUsername, cUser);
  strcpy(cPassword, cPass);

  if(strcmp(cUsername, "admin") == 0 && strcmp(cPassword, "adminpass") == 0)
  {
    authentication = 1;
  }
  if(authentication)
  {
    cout << "Access granted\n";
    cout << (char)authentication;
  } 
  else 
  {
    cout << "Wrong username and password\n";
  }

  system("pause");
  goto begin;
}
 #include <iostream>

int main( void )
{
 int authentication = 0;
 char cUsername[ 10 ];
 char cPassword[ 10 ];

 std::cout << "Username: ";
 std::cin >> cUsername;

 std::cout << "Pass: ";
 std::cin >> cPassword;

 if( std::strcmp( cUsername, "admin" ) == 0 && std::strcmp( cPassword, "adminpass" ) == 0 )
 {
  authentication = 1;
 }
 if( authentication )
 {
  std::cout << "Access granted\n";
  std::cout << ( char )authentication;
 }
 else
 {
  std::cout << "Wrong username and password\n";
 }

 return ( 0 ); 


  00000001`3f1f1710 4883ec68        sub     rsp,68h
00000001`3f1f1714 488b0515db0300  mov     rax,qword ptr [Prototype_Console!__security_cookie (00000001`3f22f230)]
00000001`3f1f171b 4833c4          xor     rax,rsp
00000001`3f1f171e 4889442450      mov     qword ptr [rsp+50h],rax
00000001`3f1f1723 c744243800000000 mov     dword ptr [rsp+38h],0  // This gives us address of "authentication" on stack.
00000001`3f1f172b 488d156e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x78 (00000001`3f2233a0)]
00000001`3f1f1732 488d0d47f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f1739 e8fdf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f173e 488d542428      lea     rdx,[rsp+28h] // This gives us address of "cUsername" on stack.
00000001`3f1f1743 488d0df6f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f174a e823faffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f174f 488d153e1c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x6c (00000001`3f223394)]
00000001`3f1f1756 488d0d23f00300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f175d e8d9f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f1762 488d542440      lea     rdx,[rsp+40h] // This gives us address of "cPassword" on stack.
00000001`3f1f1767 488d0dd2f00300  lea     rcx,[Prototype_Console!std::cin (00000001`3f230840)]
00000001`3f1f176e e8fff9ffff      call    Prototype_Console!ILT+365(??$?5DU?$char_traitsDstdstdYAAEAV?$basic_istreamDU?$char_traitsDstd (00000001`3f1f1172)
00000001`3f1f1773 488d15321c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x84 (00000001`3f2233ac)]
00000001`3f1f177a 488d4c2428      lea     rcx,[rsp+28h]
00000001`3f1f177f e86c420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1784 85c0            test    eax,eax
00000001`3f1f1786 751d            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f1788 488d15291c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0x90 (00000001`3f2233b8)]
00000001`3f1f178f 488d4c2440      lea     rcx,[rsp+40h]
00000001`3f1f1794 e857420000      call    Prototype_Console!strcmp (00000001`3f1f59f0)
00000001`3f1f1799 85c0            test    eax,eax
00000001`3f1f179b 7508            jne     Prototype_Console!main+0x95 (00000001`3f1f17a5)
00000001`3f1f179d c744243801000000 mov     dword ptr [rsp+38h],1
00000001`3f1f17a5 837c243800      cmp     dword ptr [rsp+38h],0
00000001`3f1f17aa 7426            je      Prototype_Console!main+0xc2 (00000001`3f1f17d2)
00000001`3f1f17ac 488d15151c0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xa0 (00000001`3f2233c8)]
00000001`3f1f17b3 488d0dc6ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17ba e87cf9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17bf 0fb6542438      movzx   edx,byte ptr [rsp+38h]
00000001`3f1f17c4 488d0db5ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17cb e825f9ffff      call    Prototype_Console!ILT+240(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f10f5)
00000001`3f1f17d0 eb13            jmp     Prototype_Console!main+0xd5 (00000001`3f1f17e5)
00000001`3f1f17d2 488d15ff1b0300  lea     rdx,[Prototype_Console!std::_Iosb<int>::end+0xb0 (00000001`3f2233d8)]
00000001`3f1f17d9 488d0da0ef0300  lea     rcx,[Prototype_Console!std::cout (00000001`3f230780)]
00000001`3f1f17e0 e856f9ffff      call    Prototype_Console!ILT+310(??$?6U?$char_traitsDstdstdYAAEAV?$basic_ostreamDU?$char_traitsDstd (00000001`3f1f113b)
00000001`3f1f17e5 33c0            xor     eax,eax
00000001`3f1f17e7 488b4c2450      mov     rcx,qword ptr [rsp+50h]
00000001`3f1f17ec 4833cc          xor     rcx,rsp
00000001`3f1f17ef e8bc420000      call    Prototype_Console!__security_check_cookie (00000001`3f1f5ab0)
00000001`3f1f17f4 4883c468        add     rsp,68h
00000001`3f1f17f8 c3              ret
 
 -----> old RSP value // Stack frame of caller of `main` is above, stack frame of main is below 

      16 bytes of
      "cPassword"
+40h
     8 bytes of "authentication"
+38h
      16 bytes of
      "cUsername"
+28h   


-----> RSP value = old RSP-68h#include <cstdio>
#include <cstring>
#include <iostream>

const char *PASSWORD_FILE = "rictro";

int main()
{
  char input[8];
  char password[8];

  std::sscanf(PASSWORD_FILE, "%s", password);

  std::cout << "Enter password: ";
  std::cin >> input;

  // Debug prints:
  // std::cout << "Address of input: " << &input << "\n";
  // std::cout << "Address of password: " << &password << "\n";
  // std::cout << "Input: " << input << "\n";
  // std::cout << "Password: " << password << "\n";

  if (std::strncmp(password, input, 8) == 0)
    std::cout << "Access granted\n";
  else
    std::cout << "Access denied\n";

  return 0;
}include <cstdio>
#include <cstring>
#include <iostream>

const char *PASSWORD_FILE = "rictro";

int main()
{
  char input[8];
  char password[8];

  std::sscanf(PASSWORD_FILE, "%s", password);

  std::cout << "Enter password: ";
  std::cin >> input;

  // Debug prints:
  // std::cout << "Address of input: " << &input << "\n";
  // std::cout << "Address of password: " << &password << "\n";
  // std::cout << "Input: " << input << "\n";
  // std::cout << "Password: " << password << "\n";

  if (std::strncmp(password, input, 8) == 0)
    std::cout << "Access granted\n";
  else
    std::cout << "Access denied\n";

  return 0;
}
 
 Username:cPassword
Pass: whatever
Access granted
1

  // std::cout << "Address of password: " << &password << "\n";
  // std::cout << "Input: " << input << "\n";
  // std::cout << "Password: " << password << "\n";

  if (std::strncmp(password, input, 8) == 0)
    std::cout << "Access granted\n";
  else
    std::cout << "Access denied\n";

  return 0;
} 

