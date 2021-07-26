package librpki

import (
	"github.com/fullsailor/pkcs7"
	"github.com/zloylos/grsync"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	TalRepo string = "/home/snake5932/GoProjects/src/RPKIValidator/files/tals/"
	Repo string = "/home/snake5932/GoProjects/src/RPKIValidator/files/repository/"
	TRepo string = "/home/snake5932/GoProjects/src/RPKIValidator/files/"
)

func FetchRsync(res *RPKI_FILE) error {
	task := grsync.NewTask(
		res.URI,
		Repo + filepath.Dir(strings.TrimPrefix(res.URI, "rsync://")),
		grsync.RsyncOptions{},
	)
	err := task.Run()
	log.Printf("downloading " + res.URI)
	if err != nil {
		log.Printf("rsync error: %v\n", err)
		return err
	}
	return nil
}

func FetchFile(res *RPKI_FILE, conv bool) ([]byte, error){
	if _, err := os.Stat(res.Path); os.IsNotExist(err) {
		err2 := FetchRsync(res)
		return nil, err2
	}
	f, err := os.Open(res.Path)
	if err != nil {
		log.Printf("os open error: %v\n", err)
		return nil, err
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		log.Printf("ReadAll error: %v\n", err)
		return data, err
	}
	err = f.Close()
	if conv {
		data, err = pkcs7.BER2DER(data)
		if err != nil {
			log.Printf("ber2der error: %v\n", err)
			return data, err
		}
	}
	return data, nil
}