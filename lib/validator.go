package librpki

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log"
	"math/big"
)

const (
	CRL = iota
	TAL
	CER
	MFT
	ROA
)

type RPKI_FILE struct {
	Type int
	PublicKey *rsa.PublicKey
	cert *x509.Certificate
	Parent string //AKI
	Trust bool
	Valid bool
	Path string
	SKI string //rsync uri for tal
	AKI string
	URI string
	Repository string //for MFT
	ASN []ASNRange
	IP [][]IPRange
	SerNum *big.Int
}

type Validator struct {
	ToExplore []*RPKI_FILE
	//by subjectKeyIdentifier
	Explored map[string]*RPKI_FILE
	Valids map[string]*RPKI_FILE
}

func (v *Validator) Add(res *RPKI_FILE, data []byte) error {
	valid, childs, err:= v.addResource(res, data)
	if err != nil {
		return err
	}
	for _, child := range childs {
		child.Parent = res.SKI
	}
	v.Explored[res.SKI] = res
	if valid {
		res.Valid = true
		v.Valids[res.SKI] = res
		for _, child := range childs {
			v.ToExplore = append(v.ToExplore, child)
		}
	}
	return nil
}

func (v *Validator) Explore() {
	for len(v.ToExplore) > 0 {
		res := v.ToExplore[0]
		v.ToExplore = v.ToExplore[1:]
		data, err := FetchFile(res, res.Type != TAL)
		if err != nil {
			log.Printf("File not readable: %v\n", err)
			continue
		}
		err = v.Add(res, data)
		if err != nil {
			log.Printf("File not added: %v\n", err)
		}
	}
}

func (v *Validator) addResource(res *RPKI_FILE, data []byte) (bool, []*RPKI_FILE, error) {
	switch res.Type {
	case TAL:
		err := DecodeTal(res, data)
		if err != nil {
			log.Printf("TAL undecoded")
			return false, nil, err
		}
		childs, err := v.AddTal(res)
		return true, childs, err
	case CER:
		sias, err := v.DecodeCert(res, data)
		if err != nil {
			log.Printf("CERT undecoded")
			return false, nil, err
		}
		valid, childs, err := v.AddCert(res, sias)
		if err != nil {
			log.Printf("CERT not added")
			return false, nil, err
		}
		return valid, childs, err
	}
	return false, nil, errors.New("unknown file type")
}