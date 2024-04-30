# Streambox

Encrypt (and decrypt) an unbounded `io.Reader` by chunking it into messages and ecrypting them with [golang.org/x/crypto/nacl /secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox).

From [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox#pkg-overview)'s docs:

> Thus large amounts of data should be chunked so that each message is small. (Each message still needs a unique nonce.) If in doubt, 16KB is a reasonable chunk size.

This is exactly what this package provides.


## Installation

```shell
go get github.com/ozkatz/streambox@latest
```

## Usage

### Encrypting an `io.Reader`

```go
package main

import (
	"io"
	"os"
	
	"github.com/ozkatz/streambox"
)

func main() {
	// this could be any other io.Reader
	fileHandler, err := os.Open("my_big_file.bin")
	if err != nil {
		panic(err)
	}

	// set up an encrypted wrapper around our io.Reader
	// please *never use this secret key*
	secretKey := [32]byte([]byte("12345678912345678912345678912345"))
	r := streambox.Encrypt(secretKey, fileHandler)

	// write it out to a file, or anything else that io.Readers do
	out, err := os.Create("my_big_file.bin.encrypted")
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(out, r); err != nil {
		panic(err)
	}
	if err := out.Close(); err != nil {
		panic(err)
    }
}

```

### Decrypting an encrypted `io.Reader`


```go
package main

import (
	"io"
	"os"
	
	"github.com/ozkatz/streambox"
)

func main() {
	// this could be any other io.Reader
	fileHandler, err := os.Open("my_big_file.bin.encrypted")
	if err != nil {
		panic(err)
	}

	// set up an encrypted wrapper around our io.Reader
	// please *never use this secret key*
	secretKey := [32]byte([]byte("12345678912345678912345678912345"))
	r := streambox.Decrypt(secretKey, fileHandler)

	// write it out to a file, or anything else that io.Readers do
	out, err := os.Create("my_big_file.bin")
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(out, r); err != nil {
		panic(err)
	}
	if err := out.Close(); err != nil {
		panic(err)
	}
}

```

## Implementation

This is a small wrapper around [`secretbox.Seal`](https://pkg.go.dev/golang.org/x/crypto@v0.22.0/nacl/secretbox#Seal) and [`secretbox.Open`](https://pkg.go.dev/golang.org/x/crypto@v0.22.0/nacl/secretbox#Open).
Since the module was designed to support small messages, this module wraps an unbounded io.Reader, chunks it into small messages to be `Seal()`-ed, and emits them as an `io.Reader` in the following strcuture:

```text
       ┌───
       │<message length (4-byte, BigEndian uint32)>  // includes both nonce and encrypted data
msg #1 │<nonce (24 random bytes)>
       │<encrypted bytes, up to 16Kb>
       └───
       ┌───
       │<message length (4-byte, BigEndian uint32)>  // includes both nonce and encrypted data
msg #2 │<nonce (24 random bytes)>
       │<encrypted bytes, up to 16Kb>
       └───
       ...
       ┌───
       │<message length (4-byte, BigEndian uint32)>  // includes both nonce and encrypted data
msg N  │<nonce (24 random bytes)>
       │<encrypted bytes, up to 16Kb>
       └───
```

When Decrypting, each message is `Open()`-ed on the fly, using the nonce and secretKey provided. 

This means that this library doesn't do any encryption itself, it simply assembles and decodes chunks of data, of variable sizes.
As such, it was also (to the best of my knowledge) not audited by a cryptographer. 

Use at your own risk.

## License

This library is distributed under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) license.
See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
