package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
	"github.com/ivoras/gomagiclink"
)

// Stores data in a flat directory with files named like $<userid>$<email>.json
type FileSystemStorage struct {
	Directory      string
	ID2Filename    map[uuid.UUID]string
	Email2Filename map[string]string
}

// Files are named like $USER_ID$EMAIL.json
var reUserEmailFilename = regexp.MustCompilePOSIX("_(.+?)_(.+)\\.json")

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
		ID2Filename:    map[uuid.UUID]string{},
		Email2Filename: map[string]string{},
	}
	// Read existing files
	files, err := filepath.Glob(fmt.Sprintf("%s/_*.json", dir))
	if err != nil {
		return nil, err
	}
	for f := range files {
		m := reUserEmailFilename.FindStringSubmatch(files[f])
		if m == nil {
			return nil, fmt.Errorf("cannot parse filename: %s", files[f])
		}
		id, err := uuid.Parse(m[1])
		if err != nil {
			return nil, err
		}
		result.ID2Filename[id] = files[f]
		result.Email2Filename[m[2]] = files[f]
	}

	return
}

func (fss *FileSystemStorage) StoreUser(user *gomagiclink.AuthUserRecord) (err error) {
	fileName := fmt.Sprintf("%s/%s.json", fss.Directory, user.GetKeyName())
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(user)
	fss.Email2Filename[user.Email] = fileName
	fss.ID2Filename[user.ID] = fileName
	return
}

func (fss *FileSystemStorage) getUserFromFileName(fileName string) (user *gomagiclink.AuthUserRecord, err error) {
	f, err := os.Open(fmt.Sprintf("%s/%s", fss.Directory, fileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	user = &gomagiclink.AuthUserRecord{}
	err = json.NewDecoder(f).Decode(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (fss *FileSystemStorage) GetUserById(id uuid.UUID) (user *gomagiclink.AuthUserRecord, err error) {
	fileName, ok := fss.ID2Filename[id]
	if !ok {
		return nil, gomagiclink.ErrUserNotFound
	}
	return fss.getUserFromFileName(fileName)
}

func (fss *FileSystemStorage) GetUserByEmail(email string) (user *gomagiclink.AuthUserRecord, err error) {
	fileName, ok := fss.Email2Filename[gomagiclink.NormalizeEmail(email)]
	if !ok {
		return nil, gomagiclink.ErrUserNotFound
	}
	return fss.getUserFromFileName(fileName)
}

func (fss *FileSystemStorage) UserExistsByEmail(email string) (exists bool) {
	_, exists = fss.Email2Filename[gomagiclink.NormalizeEmail(email)]
	return
}

func (fss *FileSystemStorage) GetUserCount() (int, error) {
	return len(fss.Email2Filename), nil
}

func (fss *FileSystemStorage) UsersExist() (bool, error) {
	return len(fss.Email2Filename) > 0, nil
}
