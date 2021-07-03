# PicoCTF "Hurry up! Wait!"

This is a relatively easy reverse engineering challenge from picoCTF 2021 (iirc)

We recieve a file that is decievingly named `svchost.exe`. This is in fact an x64 linux binary.
Opening up the file in ida, we see that main looks as follows...

```c
__int64 __fastcall main(int argc, char **argv, char **envp)
{
  char v4[8]; // [rsp+28h] [rbp-8h] BYREF

  gnat_argc = argc;
  gnat_argv = (__int64)argv;
  gnat_envp = (__int64)envp;
  __gnat_initialize(v4);
  sub_1D7C();
  sub_298A();
  sub_1D52();
  __gnat_finalize();
  return (unsigned int)gnat_exit_status;
}
```

Looking at the three functions, the second one (`sub_298A`) seems to be calling a huge amount of functions...
Decompiling each function seems that each is printing a character, and looks like so when decompiled.

```c
__int64 SUB_230A()
{
  return ada__text_io__put__4((_ptr *)&unk_2CC9);
}
```

`&unk_2CC9` is just a reference to `0x61` which is equal to `'a'`. Renaming all of these functions to their corresponding ascii output gives us the flag...

```c
__int64 print_flag()
{
  ada__calendar__delays__delay_for(1000000000000000LL);
  flag_p();
  flag_i();
  flag_c();
  flag_o();
  flag_C();
  flag_T();
  flag_F();
  flag_openbracket();
  flag_d();
  flag_1();
  flag_5();
  flag_a();
  flag_5();
  flag_m();
  flag_underscore();
  flag_f();
  flag_t();
  flag_w();
  flag_underscore();
  flag_0();
  flag_e();
  flag_7();
  flag_4();
  flag_c();
  flag_d();
  flag_4();
  return flag_closebracket();
}
```

Thus, we get the flag `picoCTF{d15a5m_ftw_0e74cd4}`
