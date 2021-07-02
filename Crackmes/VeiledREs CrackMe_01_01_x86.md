Writeup to VieldRE's CrackMe_01_01_x86 (https://crackmes.one/crackme/60ca0fd933c5d410b8842e6f)

Twitter: @0xLegacyy
Github: iiLegacyyii

Open up the binary in IDA and we get the following decompilation of _main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // si
  unsigned int v4; // eax
  int v5; // eax
  unsigned int i; // esi
  int result; // eax
  char v8; // [esp-4h] [ebp-44h]
  char v9; // [esp-4h] [ebp-44h]
  char Arglist[24]; // [esp+0h] [ebp-40h] BYREF
  _DWORD v11[7]; // [esp+18h] [ebp-28h] BYREF
  char ArgList[6]; // [esp+34h] [ebp-Ch] BYREF

  sub_121020("\n(@vailedre 2021)\n\n", Arglist[0]);
  sub_121020("PASSWORD: ", v8);
  sub_121050("%s", (char)Arglist);
  v4 = 16;
  strcpy((char *)&v11[5], "R+m_");
  *(__m128i *)&v11[1] = _mm_add_epi8((__m128i)xmmword_122160, (__m128i)xmmword_122180);
  do
    *((_BYTE *)&v11[1] + v4++) += 5;
  while ( v4 < 0x14 );
  v5 = strcmp(Arglist, (const char *)&v11[1]);
  if ( v5 )
    v5 = v5 < 0 ? -1 : 1;
  if ( v5 )
  {
    sub_121020("RESULT: TRY AGAIN!\n\n\n", Arglist[0]);
    result = 0;
  }
  else
  {
    v9 = v3;
    strcpy(ArgList, "FLAG:");
    sub_121020("\n%s ", (char)ArgList);
    strcpy((char *)v11, "q`dg`_m`v((((((((v(((#;x");
    for ( i = 0; i < 0x18; ++i )
      sub_121020("%c", *((_BYTE *)v11 + i) + 5);
    sub_121020("\n\n\n", v9);
    result = 0;
  }
  return result;
}
```

Looking at the line `v5 = strcmp(Arglist, (const char *)&v11[1]);` we should be able to read the password directly off of the stack
I then set a breakpoint here, and after inputting a fake password, I synchronized the stack view with esp and found the password in plaintext
```
00 00 00 00 00 00 00 00  1C FA D3 00 10 FA D3 00  .........úÓ..úÓ.
7E 10 12 00 03 00 00 00  00 00 00 00 F0 02 AE 75  ~...........ð.:registered:u
2C 21 12 00 00 00 00 00  1C FA D3 00 78 69 F3 00  ,!.......úÓ.xió.
6C FA D3 00 C4 10 12 00  2C 21 12 00 2C FA D3 00  lúÓ.Ä...,!..,úÓ.
15 00 00 00 20 21 12 00  0C 21 12 00 61 73 64 61  .... !...!..asda
73 64 00 00 DA AB 9F 75  00 00 00 00 D0 20 12 00  sd..Ú«Ÿu....Ð ..
00 00 00 00 88 12 12 00  54 68 31 36 5F 69 73 5F  ....ˆ...Th16_is_
74 48 33 5F 50 61 73 73  57 30 72 64 00 AC 9F 75  tH3_PassW0rd.¬Ÿu
00 A0 B3 00 1C 14 12 00  7E 11 CC 07 B4 FA D3 00  . ³.....~.Ì.´úÓ.
```
As we can see, the password is "Th16_is_tH3_PassW0rd". 

Running the binary again and entering the password gives us the flag! (FLAG: veiledre{--------{---(@})
