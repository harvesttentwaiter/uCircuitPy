package main

import(
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if (len(os.Args) == 1) {
		fmt.Printf("give command\n");
	} else if (os.Args[1] == "test") {
		test();
	} else if (os.Args[1] == "sign") {
		sig:=sign(os.Args[2], os.Args[3], os.Args[4])
		fmt.Printf("%s\n",sig)
	} else if (os.Args[1] == "verify") {
		rv:=verify(os.Args[2], os.Args[3], os.Args[4])
		if rv {
			fmt.Println("good")
		} else {
			fmt.Println("fail")
		}
	}
}

func test() {
	pub:="c2acd61aafc7ef8b7c98cf433289969a10af72f94f50ac5f28aaed3dab6429ca";
	sec:="3045a8208b908626b555ff4cf9af0a7c6bb1821560329c60a94ff52fd3f2955a5e874dd57f43dee016adfcbd9741e134162af86cc34ed084535936b17c6b5dbb";
	msg:="binky55";
	gold:="06468f4e23ff9450bf182b78b90e3458e40b1c13a2b591d488aa95698c50a1a9fde52b9602c6455ea47f51961fc70c0b35a7167591337efa3046af747bc95504";
	bad:="16468f4e23ff9450bf182b78b90e3458e40b1c13a2b591d488aa95698c50a1a9fde52b9602c6455ea47f51961fc70c0b35a7167591337efa3046af747bc95504";

	// bd001c41eb8b189bbd0ff262867c3da7853682b29828396229ccaf865d9d36050b727e15672ed9fa7fa6929e8acaf73335c18f958730aedc27ca9ffd1638b805

	sig := sign(pub, sec, msg);

	if sig == gold {
		fmt.Println("good gold")
	} else {
		fmt.Println("fail gold")
	}

	rv := verify(pub, sig, msg);
	if rv {
		fmt.Println("good verify")
	} else {
		fmt.Println("fail verify")
	}

	rv = verify(pub, bad, msg);
	if !rv {
		fmt.Println("good negVerify")
	} else {
		fmt.Println("fail negVerify")
	}
}
func sign(pubH string, secH string, msg string) string {
/*
 * 
data, err := hex.DecodeString(s)
if err != nil {
    panic(err)
}
fmt.Printf("% x", data)
 * */
	sec, _ := hex.DecodeString(secH)
	sigB := ed25519.Sign(sec, []byte(msg))
	return fmt.Sprintf("%x", sigB)
}


/* GenerateKey(rand io.Reader ) (PublicKey, PrivateKey, error)
 * // set rand=nil
 * 
 * func Sign(privateKey PrivateKey, message []byte) []byte

Sign signs the message with privateKey and returns a signature. It will panic if len(privateKey) is not PrivateKeySize.
func Verify 1.13

func Verify(publicKey PublicKey, message, sig []byte) bool
 * */

func verify(pubH string, sigH string, msg string) bool {
	pub, _ := hex.DecodeString(pubH)
	sig, _ := hex.DecodeString(sigH)
	goodSig := ed25519.Verify(pub, []byte(msg), sig)
	if goodSig {
		fmt.Println("good sig")
	} else {
		fmt.Println("fail sig")
	}
	return goodSig
}
