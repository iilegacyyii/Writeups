# Convert hex to base64
The string:  
`49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`

Should produce:  
`SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`  

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

# Solution
I have used these challenges to learn go, and thus my solution simply creates a simple wrapper around two go modules, allowing for decoding 
hex strings into bytes, and encoding bytes into base64.
```go
package main

import (
    "fmt"
    "encoding/hex"
    "encoding/base64"
)


func decode_hex(h string) []byte {
    hexString, err := hex.DecodeString(h);
    if (err != nil) {
        fmt.Println("Error converting hex string to byte. ", err);
        return nil;
    }
    return hexString;
}


func encode_b64(b64 []byte) string {
    return base64.StdEncoding.EncodeToString(b64);
}


func main() {
    var hex_str string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    bytes := decode_hex(hex_str);
    base64 := encode_b64(bytes);
    fmt.Println(base64);
}
```
