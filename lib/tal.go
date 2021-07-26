package librpki

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"strings"
)

var (
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func (v *Validator) AddTal(tal *RPKI_FILE) ([]*RPKI_FILE, error) {
	var files []*RPKI_FILE
	files = append(files, &RPKI_FILE{
		Type:      CER,
		Trust:     true,
		Valid:     false,
		URI:       tal.SKI,
	})
	for _, item := range files {
		item.Path = Repo + strings.TrimPrefix(item.URI, "rsync://")
	}
	return files, nil
}

func DecodeTal(tal *RPKI_FILE, data []byte) error {
	buf := bytes.NewBufferString(string(data))
	url, err := buf.ReadString('\n')
	if err != nil {
		return err
	}
	url = strings.TrimSpace(url)
	_, err = buf.ReadString('\n')
	if err != nil {
		return err
	}
	tal.SKI = url

	b64, err := buf.ReadString('\n')
	b64 = strings.TrimSpace(b64)
	for err == nil {
		var b64tmp string
		b64tmp, err = buf.ReadString('\n')
		b64tmp = strings.TrimSpace(b64tmp)
		b64 += b64tmp
	}
	if err != io.EOF {
		return err
	}
	spki, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	type subjectPublicKeyInfo struct {
		Alg struct {
			OID asn1.ObjectIdentifier
		}
		BS asn1.BitString
	}
	var info subjectPublicKeyInfo
	_, err = asn1.Unmarshal(spki, &info)
	if err != nil {
		return err
	}
	if info.Alg.OID.Equal(RSA) {
		var publicKey rsa.PublicKey
		_, err = asn1.Unmarshal(info.BS.Bytes, &publicKey)
		tal.PublicKey = &publicKey
		if err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}

func checkCertTal(certKey, talKey *rsa.PublicKey) bool {
	return certKey.N.Cmp(talKey.N) == 0 && certKey.E == talKey.E
}