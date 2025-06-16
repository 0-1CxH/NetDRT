from netdrt.cipher import NetDRTCipher

def test_keygen():
    c1 = NetDRTCipher() 
    ret1 = c1.keygen("default")
    
    c2 = NetDRTCipher() 
    ret2 = c2.keygen("default")
    
    c3 = NetDRTCipher() 
    ret3 = c3.keygen("custom", "salt")

    c4 = NetDRTCipher("salt") 
    ret4 = c4.keygen("custom")
    
    print(ret1, ret2, ret1 == ret2)
    print(ret3, ret4, ret3 == ret4)


    cp1 = c1.encrypt("hello1")
    print(c2.decrypt(cp1))
    cp2 = c2.encrypt("hello2")
    print(c1.decrypt(cp2))

    
    cp3 = c3.encrypt("hello3")
    print(c4.decrypt(cp3))
    cp4 = c4.encrypt("hello4")
    print(c3.decrypt(cp4))


    

if __name__ == "__main__":
    test_keygen()