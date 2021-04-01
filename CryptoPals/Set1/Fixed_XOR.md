# Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.  

If your function works properly, then when you feed it the string:  
`1c0111001f010100061a024b53535009181c`  
... after hex decoding, and when XOR'd against:  
`686974207468652062756c6c277320657965`  
... should produce:  
`746865206b696420646f6e277420706c6179`

# Solution
For this challenge I simply created a function that takes two byte arrays (b1, b2) and a given length (n). It then performs a bitwise xor on each corresponding 
element of the two arrays and stores the output in another array (res) to be returned and pretty printed to the user.
```go
package main

import (
    "fmt"
    "encoding/hex"
)


// decode hex string to bytes
func decode_hex(h string) []byte {
    hexString, err := hex.DecodeString(h);
    if (err != nil) {
        fmt.Println("Error converting hex string to byte. ", err);
        return nil;
    }
    return hexString;
}


// encode bytes to hex string
func encode_hex(b []byte) string {
    return hex.EncodeToString(b);
}


// xor two equal length byte arrays
func xor_bytes(b1 []byte, b2 []byte, n int) []byte {
    res := make([]byte, n)
    for i := 0; i < n; i++ {
        res[i] = b1[i] ^ b2[i];
    }
    return res;
}


func main() {
    // convert the hex strings to bytes.
    h1, h2 := "1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965";
    b1, b2 := decode_hex(h1), decode_hex(h2);
    
    // xor them together, then output.
    b1_xor_b2 := xor_bytes(b1, b2, len(b1));
    fmt.Println(encode_hex(b1_xor_b2));
    // Outputs 746865206b696420646f6e277420706c6179, as required :)
}
```
