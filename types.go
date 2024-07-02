package gomagiclink

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

type RecordWithID interface {
	GetID() ulid.ULID
}

type RecordWithKeyName interface {
	GetKeyName() string
}

type UserAuthDatabase interface {
	StoreUser(user AuthUserRecord) error
	GetUser(id ulid.ULID) (*AuthUserRecord, error)
	GetUserByEmail(email string) (*AuthUserRecord, error)
}

type AuthRecordDatabase interface {
	StoreRecord(rec AuthRecord) error
	GetRecord(id ulid.ULID) (*AuthRecord, error)
}

const challengeSignature = "9"

var ErrSecretKeyTooShort = errors.New("secret Key too short (min 16 bytes)")
var ErrInvalidChallenge = errors.New("invalid challenge")
var ErrBrokenChallenge = errors.New("broken challenge")

type AuthMagicLinkConfig struct {
	secretKeyHash        []byte
	challengeExpDuration time.Duration
}

func NewAuthMagicLinkConfig(secretKey []byte, challengeExpDuration time.Duration) (mlc *AuthMagicLinkConfig, err error) {
	if len(secretKey) < 16 {
		return nil, ErrSecretKeyTooShort
	}
	keyHash := sha256.Sum256(secretKey)
	return &AuthMagicLinkConfig{
		secretKeyHash:        keyHash[:],
		challengeExpDuration: challengeExpDuration,
	}, nil
}

func (mlc *AuthMagicLinkConfig) makeHMAC(payload []byte) []byte {
	mac := hmac.New(sha256.New, mlc.secretKeyHash)
	mac.Write(payload)
	return mac.Sum(nil)
}

// AuthUser represents user data
type AuthUserRecord struct {
	ID              ulid.ULID `json:"id"`    // Unique identifier, used to link to AuthRecords
	Email           string    `json:"email"` // Also must be unique
	Enabled         bool      `json:"enabled"`
	FirstLoginTime  time.Time `json:"first_login_time"`
	RecentLoginTime time.Time `json:"recent_login_time"`
	CustomData      any       `json:"custom_data"` // Apps can attach any kind of custom data to the user record
}

func NewAuthUserRecord(email string, customData any) (aur *AuthUserRecord, err error) {
	now := time.Now()
	aur = &AuthUserRecord{
		ID:              ulid.Make(),
		Email:           strings.ToLower(strings.TrimSpace(email)),
		Enabled:         true,
		FirstLoginTime:  now,
		RecentLoginTime: now,
		CustomData:      customData,
	}
	return aur, nil
}

func (aur *AuthUserRecord) GetID() ulid.ULID {
	if IsZeroULID(aur.ID) {
		aur.ID = ulid.Make()
	}
	return aur.ID
}

func (aur *AuthUserRecord) GetKeyName() string {
	if IsZeroULID(aur.ID) {
		aur.ID = ulid.Make()
	}
	return fmt.Sprintf("$%s$%s", aur.ID.String(), aur.Email)
}

func (aur *AuthUserRecord) GenerateChallenge(cfg *AuthMagicLinkConfig) (challenge string, err error) {
	// Challenge is of the format:
	// 9SALTED_EMAIL-SALT-EXPTIME-HMAC(EXPTIME || SALTED_EMAIL, secredKeyHash)
	salt := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}
	saltedEmailHash := sha256.Sum256(slices.Concat([]byte(aur.Email), []byte{0}, salt))
	expTime := time.Now().Add(cfg.challengeExpDuration).Unix()
	hmac := cfg.makeHMAC(slices.Concat([]byte(strconv.Itoa(int(expTime))), []byte{0}, saltedEmailHash[:]))
	challenge = fmt.Sprintf("%s%s-%s-%d-%s", challengeSignature, base32.StdEncoding.EncodeToString(saltedEmailHash[:]), base32.StdEncoding.EncodeToString(salt), expTime, base32.StdEncoding.EncodeToString(hmac))
	return challenge, nil
}

func (aur *AuthUserRecord) VerifyChallenge(cfg *AuthMagicLinkConfig, challenge string) (err error) {
	parts := strings.Split(challenge, "-")
	if len(parts) != 3 {
		return ErrInvalidChallenge
	}
	if !strings.HasPrefix(parts[0], challengeSignature) {
		return ErrInvalidChallenge
	}
	parts[0] = parts[0][len(challengeSignature):]
	saltedEmailHash, err := base32.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrInvalidChallenge
	}
	salt, err := base32.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidChallenge
	}
	hmac1, err := base32.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrInvalidChallenge
	}
	actualSaltedEmailHash := sha256.Sum256(slices.Concat([]byte(aur.Email), []byte{0}, salt))
	if !bytes.Equal(actualSaltedEmailHash[:], saltedEmailHash) {
		return ErrBrokenChallenge
	}
	hmac2 := cfg.makeHMAC(saltedEmailHash)
	if !hmac.Equal(hmac1, hmac2) {
		return ErrBrokenChallenge
	}
	return nil
}

// AuthRecord is stored in the auth database
type AuthRecord struct {
	ID         ulid.ULID `json:"id"`      // Unique identifier
	UserID     ulid.ULID `json:"user_id"` // Link to AuthUser
	ExpireTime time.Time `json:"expire_time"`
	JWT        string    `json:"jwt"`
}

func (ar *AuthRecord) GetID() ulid.ULID {
	if IsZeroULID(ar.ID) {
		ar.ID = ulid.Make()
	}
	return ar.ID
}

func (ar *AuthRecord) GetKeyName() string {
	if IsZeroULID(ar.ID) {
		ar.ID = ulid.Make()
	}
	return ar.ID.String()
}
