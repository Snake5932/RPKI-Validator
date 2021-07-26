package librpki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

var (
	MF = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 10}
	CARepo = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	SubjInfoAcc = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	IpAddrBlock = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
	ASId = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 8}
)

type SIA struct {
	AccessMethod asn1.ObjectIdentifier
	AccessLocation []byte `asn1:"tag:6"`
}

type ASNRange struct {
	Min int
	Max int
}

type IPRange struct {
	Min net.IP
	Max net.IP
}

func (v *Validator) DecodeAsns(cert_file *RPKI_FILE, data []byte) ([]ASNRange, error) {
	var asRange []ASNRange
	type ASIdentifiers struct {
		AsNum asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	var asIdentifiers ASIdentifiers
	_, err := asn1.Unmarshal(data, &asIdentifiers)
	if err != nil {
		log.Printf("Can't unmarshal asIdentifiers")
		return nil, err
	}
	var As asn1.RawValue
	_, err = asn1.Unmarshal(asIdentifiers.AsNum.Bytes, &As)
	if As.Tag == asn1.TagNull {

		asRange = make([]ASNRange, len(v.Valids[cert_file.Parent].ASN))
		copy(asRange, v.Valids[cert_file.Parent].ASN)
		return asRange, nil

	} else if As.Tag == asn1.TagSequence {
		var asIdOrRange []asn1.RawValue
		_, err := asn1.Unmarshal(As.FullBytes, &asIdOrRange)
		if err != nil {
			log.Printf("Can't unmarshal asIdOrRange")
			return nil, err
		}
		for _, aIDoR := range asIdOrRange {
			if aIDoR.Tag == asn1.TagInteger {
				fmt.Println("+")
				var as int
				_, err := asn1.Unmarshal(aIDoR.FullBytes, &as)
				if err != nil {
					log.Printf("Can't unmarshal ASId: %v\n", err)
					continue
				}
				asRange = append(asRange, ASNRange{Min: as,
												   Max: as})
			} else if aIDoR.Tag == asn1.TagSequence {
				var asr ASNRange
				_, err := asn1.Unmarshal(aIDoR.FullBytes, &asr)
				if err != nil {
					log.Printf("Can't unmarshal ASIdRange: %v\n", err)
					continue
				}
				asRange = append(asRange, asr)
			}
		}
	}
	return asRange, nil
}

func DecodeIP(family []byte, addrPrefix asn1.BitString) (IPRange, error) {
	var ipRange IPRange
	if len(family) >= 2 && (family[1] == 1 || family[1] == 2) {
		size := 4
		if family[1] == 2 {
			size = 16
		}
		ipAddr := make([]byte, size)
		copy(ipAddr, addrPrefix.Bytes)
		ip := net.IP(ipAddr)
		mask := net.CIDRMask(addrPrefix.BitLength, size * 8)
		min := make([]byte, len(ip))
		max := make([]byte, len(ip))
		for i := range []byte(ip) {
			min[i] = ip[i] & mask[i]
			max[i] = ip[i] | ^mask[i]
		}
		ipRange.Min = min
		ipRange.Max = max
		return ipRange, nil
	} else {
		log.Printf("Not an IP (from DecodeIP)")
		return ipRange, errors.New("not an ip")
	}
}

func DecodeIpMin(family []byte, addr asn1.BitString) (net.IP, error) {
	if len(family) >= 2 && (family[1] == 1 || family[1] == 2) {
		size := 4
		if family[1] == 2 {
			size = 16
		}
		ipAddr := make([]byte, size)
		copy(ipAddr, addr.Bytes)
		return ipAddr, nil
	} else {
		log.Printf("Not an IP (from DecodeIpMin)")
		return net.IP{}, errors.New("not an ip")
	}
}

func DecodeIpMax(family []byte, addr asn1.BitString) (net.IP, error) {
	if len(family) >= 2 && (family[1] == 1 || family[1] == 2) {
		size := 4
		if family[1] == 2 {
			size = 16
		}
		ipAddr := make([]byte, size)
		copy(ipAddr, addr.Bytes)
		for i := addr.BitLength / 8 + 1; i < size; i++ {
			ipAddr[i] = 0xFF
		}
		if addr.BitLength / 8 < size {
			ipAddr[addr.BitLength / 8] |= 0xFF >> uint(addr.BitLength % 8)
		}
		return ipAddr, nil
	} else {
		log.Printf("Not an IP (from DecodeIpMax)")
		return net.IP{}, errors.New("not an ip")
	}
}

func (v *Validator) DecodeIPs(cert_file *RPKI_FILE, data []byte) ([][]IPRange, error) {
	var ipRange [][]IPRange
	ipRange = make([][]IPRange, 2)
	type IPAddrFamily struct {
		AddressFamily []byte
		IpAddressChoice asn1.RawValue
	}
	var ipAddrFamSeq []IPAddrFamily
	_, err := asn1.Unmarshal(data, &ipAddrFamSeq)
	if err != nil {
		log.Printf("IPAddrFamily seq Unmarshal error")
		return ipRange, err
	}
	for _, ipAddrFam := range ipAddrFamSeq {
		if ipAddrFam.IpAddressChoice.Tag == asn1.TagNull {

			ipRange[ipAddrFam.AddressFamily[1] - 1] = make([]IPRange, len(v.Valids[cert_file.Parent].IP[ipAddrFam.AddressFamily[1] - 1]))
			copy(ipRange[ipAddrFam.AddressFamily[1] - 1], v.Valids[cert_file.Parent].IP[ipAddrFam.AddressFamily[1] - 1])

		} else if ipAddrFam.IpAddressChoice.Tag == asn1.TagSequence {
			var ipAddrOrRangeSeq []asn1.RawValue
			_, err := asn1.Unmarshal(ipAddrFam.IpAddressChoice.FullBytes, &ipAddrOrRangeSeq)
			if err != nil {
				log.Printf("ipAddrOrRange seq Unmarshal error")
				return ipRange, err
			}
			for _, ipAddrOrRange := range ipAddrOrRangeSeq {
				if ipAddrOrRange.Tag == asn1.TagBitString {
					var addrPrefix asn1.BitString
					_, err := asn1.Unmarshal(ipAddrOrRange.FullBytes, &addrPrefix)
					if err != nil {
						log.Printf("addrPrefix Unmarshal error: %v\n", err)
						continue
					}
					IpRange, err := DecodeIP(ipAddrFam.AddressFamily, addrPrefix)
					if err != nil {
						log.Printf("IPprefix decoding error: %v\n", err)
						continue
					}
					ipRange[ipAddrFam.AddressFamily[1] - 1] = append(ipRange[ipAddrFam.AddressFamily[1] - 1], IpRange)
				} else if ipAddrOrRange.Tag == asn1.TagSequence {
					type IPAddrRange struct {
						MIN asn1.BitString
						MAX asn1.BitString
					}
					var ipAddrRange IPAddrRange
					_, err := asn1.Unmarshal(ipAddrOrRange.FullBytes, &ipAddrRange)
					if err != nil {
						log.Printf("IPAddrRange UnMarshal error: %v\n", err)
						continue
					}
					min, err := DecodeIpMin(ipAddrFam.AddressFamily, ipAddrRange.MIN)
					if err != nil {
						log.Printf("IPAddrMin decode error: %v\n", err)
						continue
					}
					max, err := DecodeIpMax(ipAddrFam.AddressFamily, ipAddrRange.MAX)
					if err != nil {
						log.Printf("IPAddrMax decode error: %v\n", err)
						continue
					}
					IpRange := IPRange {
						Min:	min,
						Max:	max,
					}
					ipRange[ipAddrFam.AddressFamily[1] - 1] = append(ipRange[ipAddrFam.AddressFamily[1] - 1], IpRange)
				}
			}
		}
	}
	return ipRange, nil
}

func DecodeSias(data []byte) ([]SIA, error) {
	var sias []SIA
	_, err := asn1.Unmarshal(data, &sias)
	if err != nil {
		log.Printf("SIA Unmarshal error")
		return sias, err
	}
	return sias, nil
}

func (v *Validator) DecodeCert(cert_file *RPKI_FILE, data []byte) ([]SIA, error) {
	var sias []SIA
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		log.Printf("Can't parse cert")
		return sias, err
	}
	cert_file.cert = cert
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(IpAddrBlock) {
			ips, err := v.DecodeIPs(cert_file, ext.Value)
			if err != nil {
				log.Printf("Can't parse IPs")
				return sias, err
			}
			cert_file.IP = make([][]IPRange, 2)
			for i := 0; i < 2; i++ {
				cert_file.IP[i] = make([]IPRange, len(ips[i]))
			}
			copy(cert_file.IP, ips)
		} else if ext.Id.Equal(ASId) {
			asns, err := v.DecodeAsns(cert_file, ext.Value)
			if err != nil {
				log.Printf("Can't parse ASNs")
				return sias, err
			}
			cert_file.ASN = make([]ASNRange, len(asns))
			copy(cert_file.ASN, asns)
		} else if ext.Id.Equal(SubjInfoAcc) {
			sias, err = DecodeSias(ext.Value)
			if err != nil {
				log.Printf("Can't parse sia")
				return sias, err
			}
		}
	}
	cert_file.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	cert_file.AKI = string(cert.AuthorityKeyId)
	if cert_file.AKI == "" && !cert_file.Trust {
		log.Printf("Cert has no AKI and we can't trust it")
		return sias, errors.New("cert has no aki and we can't trust it")
	}
	cert_file.SKI = string(cert.SubjectKeyId)
	if cert_file.SKI == "" {
		log.Printf("Cert has no SKI")
		return sias, errors.New("cert has no ski")
	}
	cert_file.SerNum = cert.SerialNumber
	return sias, nil
}

func (v *Validator) AddCert(cert_file *RPKI_FILE, sias []SIA) (bool, []*RPKI_FILE, error) {
	if cert_file.Parent != "" && v.Valids[cert_file.Parent].Type == TAL {
		talValid := checkCertTal(cert_file.PublicKey, v.Valids[cert_file.Parent].PublicKey)
		if !talValid {
			log.Printf("Failed validation against TAL")
			return false, nil, errors.New("failed validation against tal")
		}
	}
	valid, err := v.ValidateCert(cert_file)
	if err != nil {
		log.Printf("Validation error")
		return false, nil, err
	}
	var files []*RPKI_FILE
	var uri, repo string
	mftPresent := false
	CARepoPresent := false
	CRLPresent := false
	for _, sia := range sias {
		if sia.AccessMethod.Equal(MF) {
			uri = string(sia.AccessLocation)
			mftPresent = true
		}
		if sia.AccessMethod.Equal(CARepo) {
			repo = string(sia.AccessLocation)
			CARepoPresent = true
		}
	}
	files = append(files, &RPKI_FILE{
		Type: MFT,
		Trust: false,
		Valid: false,
		URI: uri,
		Repository: repo,
	})
	for _, crldp := range cert_file.cert.CRLDistributionPoints {
		CRLPresent = true
		files = append(files, &RPKI_FILE{
			Type: CRL,
			Trust: false,
			Valid: false,
			URI: crldp,
		})
	}
	for _, file := range files {
		file.Path = Repo + strings.TrimPrefix(file.URI, "rsync://")
	}

	if !mftPresent || !CARepoPresent || (!CRLPresent && !cert_file.Trust) {
		log.Println("SIA validation failed")
		return false, nil, nil
	}
	return valid, files, nil
}

func (v *Validator) ValidateCert(cert_file *RPKI_FILE) (bool, error) {
	if !checkFields(cert_file) {
		log.Printf("Fields don't match")
		return false, errors.New("fields don't match")
	}
	_, hasParent := v.Valids[cert_file.AKI]
	if (!hasParent || cert_file.AKI != cert_file.Parent) && !cert_file.Trust {
		log.Printf("File has no valid parent and we can't trust it")
		return false, errors.New("file has no valid parent and we can't trust it")
	}
	//time
	t := time.Now().UTC()
	after := t.After(cert_file.cert.NotBefore)
	before := t.Before(cert_file.cert.NotAfter)
	if !(before && after) {
		log.Printf("Time validation fail")
		return false, errors.New("time validation fail")
	}
	if cert_file.Trust {
		return true, nil
	}
	//parentSign
	err := cert_file.cert.CheckSignatureFrom(v.Valids[cert_file.AKI].cert)
	if err != nil {
		log.Printf("Checking sign error")
		return false, err
	}
	//revocation

	//ips
	ipCheck := v.checkIP(cert_file)
	if !ipCheck {
		log.Printf("IP validation fail")
		return false, errors.New("ip validation fail")
	}
	//asns
	asnCheck := v.checkASN(cert_file)
	if !asnCheck {
		log.Printf("ASN validation fail")
		return false, errors.New("asn validation fail")
	}
	return true, nil
}

func (v *Validator) checkIP(cert_file *RPKI_FILE) bool {
	valid := true
	parent := v.Valids[cert_file.AKI]
	for _, ip := range cert_file.IP[0] {
		tValid := false
		for _, pIP := range parent.IP[0] {
			tValid = bytes.Compare(ip.Min, pIP.Min) >= 0 && bytes.Compare(ip.Max, pIP.Max) <= 0
			if tValid {
				break
			}
		}
		valid = valid && tValid
	}
	valid2 := true
	for _, ip := range cert_file.IP[1] {
		tValid := false
		for _, pIP := range parent.IP[1] {
			tValid = bytes.Compare(ip.Min, pIP.Min) >= 0 && bytes.Compare(ip.Max, pIP.Max) <= 0
			if tValid {
				break
			}
		}
		valid2 = valid2 && tValid
	}
	return valid && valid2
}

func (v *Validator) checkASN(cert_file *RPKI_FILE) bool {
	valid := true
	parent := v.Valids[cert_file.AKI]
	for _, as := range cert_file.ASN {
		tValid := false
		for _, pAs := range parent.ASN {
			tValid = as.Min >= pAs.Min && as.Max <= pAs.Max
			if tValid {
				break
			}
		}
		valid = valid && tValid
	}
	return valid
}

func checkFields(cert_file *RPKI_FILE) bool {
	if cert_file.cert.Version != 3 {
		return false
	}
	if cert_file.SerNum.String() == "" {
		return false
	}
	if cert_file.cert.PublicKeyAlgorithm != x509.RSA {
		return false
	}
	if cert_file.cert.Issuer.CommonName == "" {
		return false
	}
	if cert_file.AKI == "" && !cert_file.Trust {
		return false
	}
	if cert_file.SKI == "" {
		return false
	}
	if len(cert_file.cert.ExtKeyUsage) > 0 {
		return false
	}
	if len(cert_file.ASN) == 0 {
		return false
	}
	if len(cert_file.IP[0]) == 0 && len(cert_file.IP[1]) == 0 {
		return false
	}
	if cert_file.PublicKey == nil {
		return false
	}
	return true
}