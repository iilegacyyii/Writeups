# Crackmes.one - CrackMe_V3_Marquire

Writeup to Marquire's CrackMe_V3_Marquire (https://crackmes.one/crackme/614ef84133c5d458fcb365ff)

Twitter: @0xLegacyy
Github: iiLegacyyii

Open up the binary in IDA and we get the following decompilation of `main`.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *v3; // edx
  int v4; // eax
  char v5; // cl
  _BYTE v7[254]; // [esp+14h] [ebp-200h] BYREF
  char v8[3]; // [esp+112h] [ebp-102h] BYREF
  char v9; // [esp+115h] [ebp-FFh]
  char v10; // [esp+116h] [ebp-FEh]
  char v11; // [esp+117h] [ebp-FDh]
  char v12; // [esp+118h] [ebp-FCh]
  char v13; // [esp+119h] [ebp-FBh]
  char v14; // [esp+11Ah] [ebp-FAh]
  char v15; // [esp+11Bh] [ebp-F9h]
  char v16; // [esp+11Ch] [ebp-F8h]

  sub_401930();
  v3 = v7;
  v4 = 50;
  do
  {
    v5 = v4++;
    *v3++ = v5 ^ 3;
  }
  while ( (_BYTE)v4 != 48 );
  puts("## The goal of this crackme is to find out the right key ##\n");
  printf("Enter the key : ");
  scanf("%254s", v8);
  printf("\n\nYour input <%s> is ", v8);
  if ( v8[0] == v7[30]
    && v8[1] == v7[37]
    && v8[2] == v7[24]
    && v9 == v7[29]
    && v9 == v10
    && v11 == v7[42]
    && v12 == v7[20]
    && v13 == v7[16]
    && v8[0] == v14
    && v15 == v7[40]
    && v16 == v7[10] )
  {
    printf("right !");
  }
  else
  {
    printf("wrong !");
  }
  printf("\n\n-Pres any key to exit-");
  getch();
  return 0;
}
```

It seems our user input `v8` is being compared to `v7` at runtime. Whilst debugging, we can find the value of `v7` by setting a breakpoint just before the call to `scanf`.

```c
_BYTE v7[254] = { 0x31,0x30,0x37,0x36,0x35,0x34,0x3B,0x3A,0x39,0x38,0x3F,0x3E,0x3D,0x3C,0x43,0x42,0x41,0x40,0x47,0x46,0x45,0x44,0x4B,0x4A,0x49,0x48,0x4F,0x4E,0x4D,0x4C,0x53,0x52,0x51,0x50,0x57,0x56,0x55,0x54,0x5B,0x5A,0x59,0x58,0x5F,... };
```

One thing to keep in mind, is that our user input buffer is in fact able to overwrite the variables after it on the stack, as follows:

```c
char user_input_first3[3]; // [esp+112h] [ebp-102h] BYREF
char user_input_4; // [esp+115h] [ebp-FFh]
char user_input_5; // [esp+116h] [ebp-FEh]
char user_input_6; // [esp+117h] [ebp-FDh]
char user_input_7; // [esp+118h] [ebp-FCh]
char user_input_8; // [esp+119h] [ebp-FBh]
char user_input_9; // [esp+11Ah] [ebp-FAh]
char user_input_10; // [esp+11Bh] [ebp-F9h]
char user_input_11; // [esp+11Ch] [ebp-F8h]
```

Now we have this information, as well as knowledge of the values of `v7`, we can next look at the if statement and figure out the key!

```c
if ( user_input_first3[0] == v7[30]             // 'S'
    && user_input_first3[1] == v7[37]           // 'T'
    && user_input_first3[2] == v7[24]           // 'I'
    && user_input_4 == v7[29]                   // 'L'
    && user_input_4 == user_input_5             // 'L'
    && user_input_6 == v7[42]                   // '_'
    && user_input_7 == v7[20]                   // 'E'
    && user_input_8 == v7[16]                   // 'A'
    && user_input_first3[0] == user_input_9     // 'S'
    && user_input_10 == v7[40]                  // 'Y'
    && user_input_11 == v7[10] )                // '?'
```

With the user input variables verbosely labeled, figuring out the key is now trivial: `STILL_EASY?`

