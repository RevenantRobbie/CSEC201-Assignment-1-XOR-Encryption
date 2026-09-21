from pwn import *

XOR = process("./xor", stdin=process.PTY, stdout=process.PTY)

def testEdgecase1():
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"e")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"edgecase1.txt")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"A"*1000)
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"Z")

def testEdgecase2():
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"d")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"StandardCiphertext.txt")
    print(XOR.recvuntil(b": "))
    XOR.send(b"abc123")
    print(XOR.clean())
    XOR.interactive()

def testEdgecase3():
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"d")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"StandardCiphertext.txt")
    print(XOR.recvuntil(b": "))
    XOR.send(b"A"*500)
    print(XOR.clean())
    XOR.interactive()

def testEdgecase4():
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"e")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"A"*500)
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"A"*5)
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"Z")

def testEdgecase5():
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"e")
    print(XOR.recvuntil(b": "))
    XOR.send(b"Edgecase5.txt")
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"A"*5)
    print(XOR.recvuntil(b": "))
    XOR.sendline(b"Z")

def main():
    # print(XOR.recvuntil(b": "))
    # XOR.interactive()
    # testEdgecase1()
    # testEdgecase2()
    # testEdgecase4()
    testEdgecase5()

if __name__ == "__main__":
    main()

