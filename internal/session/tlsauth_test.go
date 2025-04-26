package session

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

const keyData = `-----BEGIN OpenVPN Static key V1-----
f5f052e38b86c44a7f190157e59e94fa
dd67c1974759d1521c2601c96a2baccc
162d549ac46d5fa7fdc45550c77d6952
04b99e30a15b7481541a9f18d9e010c5
a614a468e67a9997835bfc0644f295b9
a413f0cc6ef2e7ac3901b42ba039a9a4
51e02593b8aa059c748ac87dade38eae
bf6fa8a43caa2623225611020128917b
cf60d356a7eeb48d91b230251039a3ff
465815ec7d34d4d132446adacb75dd8c
2eb99ddae3dc5deadfe88d78ec4a52fa
df2f0706a2be4814589dcb5d3b276bf3
3654df5a7241d003f4729fece1c02793
811c4d10e06d969f9798ced2a24c2f76
c040024d19256531a37502ad3487ca8f
34335f34d61fb3be37946fa0c9ae1898
-----END OpenVPN Static key V1-----`

const (
	key0 = "a614a468e67a9997835bfc0644f295b9a413f0cc"
	key1 = "3654df5a7241d003f4729fece1c02793811c4d10"
)

func TestExtractTLSAuthKeys(t *testing.T) {
	k0, _ := hex.DecodeString(key0)
	k1, _ := hex.DecodeString(key1)

	t.Run("valid keys returned with direction=1", func(t *testing.T) {
		local, remote, err := ExtractTLSAuthKeys(keyData, 1)
		if err != nil {
			t.Errorf("got error for valid key: %v", err)
		}

		if !bytes.Equal(local[:], k1) {
			t.Errorf("incorrect local key returned got=%x want=%x", local, k1)
		}

		if !bytes.Equal(remote[:], k0) {
			t.Errorf("incorrect remote key returned got=%x want=%x", remote, k0)
		}
	})
}

func TestWriteSignature(t *testing.T) {
	var k1 model.TLSAuthKey
	pack, _ := hex.DecodeString("38529034d4d6b753b600000000000000000000000000000000000000000000000167444aed0000000000")
	want, _ := hex.DecodeString("38529034d4d6b753b69f4a9edd3182c8d4a0c07702a8f7e2e2aefba2990000000167444aed0000000000")

	hex.Decode(k1[:], []byte(key1))
	t.Run("valid hmac signature calculated", func(t *testing.T) {
		buf := bytes.NewBuffer(pack)
		WriteSignature(k1, buf)

		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("incorrect local key returned got=%x want=%x", buf.Bytes(), want)
		}
	})
}
