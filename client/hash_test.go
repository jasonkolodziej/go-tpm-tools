package client_test

import (
	"bytes"
	"crypto"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/jasonkolodziej/go-tpm-tools/client"
	"github.com/jasonkolodziej/go-tpm-tools/internal/test"
	"io"
	"reflect"
	"testing"
)

type U16Bytes []byte

var testStringByteSlice = []byte("Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of \"de Finibus Bonorum et Malorum\" (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, \"Lorem ipsum dolor sit amet..\", comes from a line in section 1.10.32. There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc.")

func TestSizedArray(t *testing.T) {
	b := U16Bytes{'a', 'b'}
	c := make([]byte, 0, 1024)
	size := uint16(len([]byte(b)))
	printSlice("b", b)
	printSlice("c", c)
	t.Log(size)

}

func TestUnsizedArray(t *testing.T) {
	const thisSize = 1514
	const maxSz = 1024
	const ch = "chuck "
	s := "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of \"de Finibus Bonorum et Malorum\" (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, \"Lorem ipsum dolor sit amet..\", comes from a line in section 1.10.32. There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc."
	b := bytes.NewBufferString(s)
	printSlice("b", b.Bytes())
	i := -1
	for k := true; k; k = b.Len() > 0 {
		i += 1
		t.Logf("size before Next: %d", b.Len())
		printSlice(fmt.Sprintf("%s%x", ch, i), b.Next(maxSz))
	}
}

func printSlice(s string, x []byte) {
	fmt.Printf("%s len=%d cap=%d %v\n",
		s, len(x), cap(x), x)
}

func TestByteSliceToBuffer(t *testing.T) {
	by := client.ByteSliceToBuffer(testStringByteSlice)
	if by.Len() != len(testStringByteSlice) {
		t.Fatalf("byte slice was length %x, while byte.Buffer was length %x", len(testStringByteSlice), by.Len())
	}
	if !reflect.DeepEqual(testStringByteSlice, by.Bytes()) {
		t.Fatalf("Deep Equal failed")
	}
	if !bytes.Equal(testStringByteSlice, by.Bytes()) {
		t.Fatalf("bytes.Equal failed")
	}
}

func TestHashWithSequencing(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	var resolve client.HashResolver = func() (hashType *crypto.Hash, rw io.ReadWriter) {
		// hash := crypto.SHA1
		return nil, rwc
	}
	handle := tpm2.HandleNull
	digest, ticket, err := client.HashWithSequencing(testStringByteSlice, resolve, "", &handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(digest)
	t.Log(ticket)
}
