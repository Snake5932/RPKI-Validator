package main

import (
	librpki "RPKIValidator/lib"
	"io/ioutil"
	"log"
)

func main() {
	v := librpki.Validator{}
	v.Explored = make(map[string]*librpki.RPKI_FILE)
	v.Valids = make(map[string]*librpki.RPKI_FILE)
	lst, _ := ioutil.ReadDir(librpki.TalRepo)
	if len(lst) == 0 {
		log.Printf("no TALs in dir")
	}
	for _, val := range lst {
		v.ToExplore = append(v.ToExplore, &librpki.RPKI_FILE{
			Type:      librpki.TAL,
			Trust:     true,
			Valid:     false,
			Path:      librpki.TalRepo + val.Name(),
		})
	}
	v.Explore()
}