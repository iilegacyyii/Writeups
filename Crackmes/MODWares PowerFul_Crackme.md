# Crackmes.one MODWare's PowerFul_Crackme

Writeup to MODWare's PowerFul_Crackme (https://crackmes.one/crackme/6141b45933c5d4649c52ba6f)

Twitter: @0xLegacyy
Github: iiLegacyyii

Open up the binary in IDA and we get the following decompilation of `main`.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  char v5[11]; // [rsp+3h] [rbp-2Dh]
  char v6[11]; // [rsp+Eh] [rbp-22h] BYREF
  char v7[19]; // [rsp+19h] [rbp-17h] BYREF
  int i; // [rsp+2Ch] [rbp-4h]

  strcpy(v7, "bpfajgobiw");
  printf("The magic string: ");
  for ( i = 0; i <= 9; ++i )
    __isoc99_scanf(" %c", &v6[i]);
  *(_DWORD *)&v7[15] = 0;
  while ( *(int *)&v7[15] <= 9 )
  {
    if ( *(int *)&v7[15] > 6 )
      v3 = *(_DWORD *)&v7[15] - 7;
    else
      v3 = *(_DWORD *)&v7[15] + 3;
    v5[v3] = v6[*(int *)&v7[15]];
    ++*(_DWORD *)&v7[15];
  }
  v6[10] = 0;
  v5[10] = 0;
  *(_DWORD *)&v7[11] = 0;
  while ( *(int *)&v7[11] <= 9 )
  {
    if ( v5[*(int *)&v7[11]] != v7[*(int *)&v7[11]] )
    {
      puts("Sorry, wrong input :(");
      return 0;
    }
    ++*(_DWORD *)&v7[11];
  }
  printf("Congratulations, correct flag!\nThe flag is: WatadCTF{%s}\n", v6);
  return 0;
}
```

### Cleaning up the code
 
 - Line 6 & 13 & 25, we see `*(_DWORD *)&v7[15] = 0;` and `*(_DWORD *)&v7[11] = 0;`, indicating that the last 8 bytes of v7 are in fact two integers.
 - Line 9, `strcpy(v7, "bpfajgobiw");` seems to be an obfuscated flag, so I renamed the variable to `obf_input`
 - Line 12, `__isoc99_scanf(" %c", &v6[i]);` is reading our user input, so rename `v7` to `user_input`

This gives us the code in the following state.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  char obf_input[11]; // [rsp+3h] [rbp-2Dh]
  char user_input[11]; // [rsp+Eh] [rbp-22h] BYREF
  char obf_flag[11]; // [rsp+19h] [rbp-17h] BYREF
  int i; // [rsp+24h] [rbp-Ch]
  int j; // [rsp+28h] [rbp-8h]
  int k; // [rsp+2Ch] [rbp-4h]

  strcpy(obf_flag, "bpfajgobiw");
  printf("The magic string: ");
  for ( k = 0; k <= 9; ++k )
    __isoc99_scanf(" %c", &user_input[k]);
  for ( j = 0; j <= 9; ++j )
  {
    if ( j > 6 )
      v3 = j - 7;
    else
      v3 = j + 3;
    obf_input[v3] = user_input[j];
  }

  user_input[10] = 0;
  obf_input[10] = 0;
  for ( i = 0; i <= 9; ++i )
  {
    if ( obf_input[i] != obf_flag[i] )
    {
      puts("Sorry, wrong input :(");
      return 0;
    }
  }
  printf("Congratulations, correct flag!\nThe flag is: WatadCTF{%s}\n", user_input);
  return 0;
}
```

### Constructing the flag

Focus on this piece of code:

```c
for ( j = 0; j <= 9; ++j )
{
    if ( j > 6 )
        v3 = j - 7;
    else
        v3 = j + 3;
    obf_input[v3] = user_input[j];
}
```

This shows us that `obf_input` will end up in the following state, based off of `user_input`, essentially "rotating" our user input right by 3.

```c
obf_input[11] = { user_input[7],user_input[8],user_input[9],user_input[0],user_input[1],user_input[2],user_input[3],user_input[4],user_input[5],user_input[6],0,0 };
```

It is then compared to `obf_input` (`"bpfajgobiw"`):

```c
for ( i = 0; i <= 9; ++i )
{
    if ( obf_input[i] != obf_flag[i] )
    {
        puts("Sorry, wrong input :(");
        return 0;
    }
}
printf("Congratulations, correct flag!\nThe flag is: WatadCTF{%s}\n", user_input);
return 0;
```

This means, the flag is: `WatadCTF{ajgobiwbpf}`.

```
./PowerFul_Crackme 
The magic string: ajgobiwbpf
Congratulations, correct flag!
The flag is: WatadCTF{ajgobiwbpf}
```