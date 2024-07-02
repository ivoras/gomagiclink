package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/ivoras/gomagiclink"
)

// Stores data in a flat directory with files named like $<userid>$<email>.json
type FileSystemStorage struct {
	Directory      string
	ID2Filename    map[string]string
	Email2Filename map[string]string
}

// Files are named like $USER_ID$EMAIL.json
var reUserEmailFilename = regexp.MustCompilePOSIX(".*/\\$(.+)\\$(.+)\\.json")

func NewFileSystemStorage(dir string) (result *FileSystemStorage, err error) {
	if dir[len(dir)-1] == '/' {
		dir = dir[0 : len(dir)-1]
	}
	_, err = os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create the directory
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				return
			}
		} else {
			return
		}
	}
	result = &FileSystemStorage{
		Directory:      dir,
		ID2Filename:    map[string]string{},
		Email2Filename: map[string]string{},
	}
	// Read existing files
	files, err := filepath.Glob(fmt.Sprintf("%s/$*.json", dir))
	if err != nil {
		return nil, err
	}
	for f := range files {
		m := reUserEmailFilename.FindStringSubmatch(files[f])
		if m == nil {
			return nil, fmt.Errorf("cannot parse filename: %s", files[f])
		}
		result.ID2Filename[m[1]] = files[f]
		result.Email2Filename[m[2]] = files[f]
	}

	return
}

func (fss *FileSystemStorage) StoreRecord(rec gomagiclink.RecordWithKeyName) (err error) {
	fileName := fmt.Sprintf("%s/%s.json", fss.Directory, rec.GetKeyName())
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(rec)
	return
}
