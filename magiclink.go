package gomagiclink

import (
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
	UserExistsByEmail(email string) bool
	StoreUser(user *AuthUserRecord) error
	GetUserById(id ulid.ULID) (*AuthUserRecord, error)
	GetUserByEmail(email string) (*AuthUserRecord, error)
}

const challengeSignature = "9"
const sessionIdSignature = "S"
const saltLength = 8

var ErrUserAlreadyExists = errors.New("user already exists")
var ErrUserNotFound = errors.New("user not found")
var ErrSecretKeyTooShort = errors.New("secret Key too short (min 16 bytes)")
var ErrInvalidChallenge = errors.New("invalid challenge")
var ErrBrokenChallenge = errors.New("broken challenge")
var ErrExpiredChallenge = errors.New("expired challenge")
var ErrInvalidSessionId = errors.New("invalid session id")
var ErrBrokenSessionId = errors.New("broken session id")
var ErrExpiredSessionId = errors.New("expired session id")

type AuthMagicLinkController struct {
	secretKeyHash        []byte
	challengeExpDuration time.Duration
	sessionExpDuration   time.Duration
	db                   UserAuthDatabase
}

// NewAuthMagicLinkController configures and creates a new instance of the AuthMagicLinkController.
// The secretKey needs to be kept safe. To provide your own storage mechanism for the magic
// link data, implement the UserAuthDatabase interface. There are file system and SQL database
// implementations provided.
func NewAuthMagicLinkController(secretKey []byte, challengeExpDuration time.Duration, sessionExpDuration time.Duration, db UserAuthDatabase) (mlc *AuthMagicLinkController, err error) {
	if len(secretKey) < 16 {
		return nil, ErrSecretKeyTooShort
	}
	keyHash := sha256.Sum256(secretKey)
	return &AuthMagicLinkController{
		secretKeyHash:        keyHash[:],
		challengeExpDuration: challengeExpDuration,
		sessionExpDuration:   sessionExpDuration,
		db:                   db,
	}, nil
}

func (mlc *AuthMagicLinkController) makeHMAC(payload []byte) []byte {
	mac := hmac.New(sha256.New, mlc.secretKeyHash)
	mac.Write(payload)
	return mac.Sum(nil)
}

func (mlc *AuthMagicLinkController) GetUserByEmail(email string) (*AuthUserRecord, error) {
	return mlc.db.GetUserByEmail(email)
}

func (mlc *AuthMagicLinkController) StoreUser(user *AuthUserRecord) error {
	return mlc.db.StoreUser(user)
}

func (mlc *AuthMagicLinkController) UserExistsByEmail(email string) bool {
	return mlc.db.UserExistsByEmail(email)
}

func (mlc *AuthMagicLinkController) GenerateChallenge(email string) (challenge string, err error) {
	// Challenge is in the format:
	// SALT-EMAIL-EXPTIME-HMAC(SALT || EMAIL || EXPTIME, secredKeyHash)
	email = NormalizeEmail(email)
	salt := make([]byte, saltLength)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}
	expTime := time.Now().Add(mlc.challengeExpDuration).Unix()
	hmac := mlc.makeHMAC(slices.Concat(salt, []byte{0}, []byte(email), []byte{0}, []byte(strconv.Itoa(int(expTime)))))
	challenge = fmt.Sprintf("%s%s-%s-%d-%s", challengeSignature, encodeToString(salt), encodeToString([]byte(email)), expTime, encodeToString(hmac))
	return challenge, nil
}

func (mlc *AuthMagicLinkController) VerifyChallenge(challenge string) (user *AuthUserRecord, err error) {
	if !strings.HasPrefix(challenge, challengeSignature) {
		return nil, ErrInvalidChallenge
	}
	challenge = challenge[len(challengeSignature):]
	parts := strings.Split(challenge, "-")
	if len(parts) != 4 {
		return nil, ErrInvalidChallenge
	}

	salt, err := decodeFromString(parts[0])
	if err != nil {
		return nil, ErrInvalidChallenge
	}
	email, err := decodeFromString(parts[1])
	if err != nil {
		return nil, ErrInvalidChallenge
	}
	expTime, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, ErrInvalidChallenge
	}
	if expTime < int(time.Now().Unix()) {
		return nil, ErrExpiredChallenge
	}
	hmac1, err := decodeFromString(parts[3])
	if err != nil {
		return nil, ErrInvalidChallenge
	}
	hmac2 := mlc.makeHMAC(slices.Concat(salt, []byte{0}, []byte(email), []byte{0}, []byte(strconv.Itoa(int(expTime)))))
	if !hmac.Equal(hmac1, hmac2) {
		return nil, ErrBrokenChallenge
	}
	// We've verified the challenge, so assume the user is real.
	// Now either create a new AuthUserRecord or load an existing one.
	user, err = mlc.db.GetUserByEmail(string(email))
	if err != nil {
		if err == ErrUserNotFound {
			user, err = NewAuthUserRecord(string(email))
		}
	}

	if user != nil {
		user.RecentLoginTime = time.Now()
	}
	return
}

func (mlc *AuthMagicLinkController) GenerateSessionId(user *AuthUserRecord) (sessionId string, err error) {
	// Session ID is in the format:
	// SALT-USER_ID-EXPTIME-HMAC(SALT || USER_ID || EXPTIME, secretKeyHash)
	salt := make([]byte, saltLength)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}
	userId := user.ID.String()
	expTime := 0
	if mlc.sessionExpDuration > 0 {
		expTime = int(time.Now().Add(mlc.sessionExpDuration).Unix())
	}
	expTimeStr := strconv.Itoa(expTime)

	hmac := mlc.makeHMAC(slices.Concat(salt, []byte{0}, user.ID.Bytes(), []byte{0}, []byte(expTimeStr)))

	return fmt.Sprintf("%s%s-%s-%s-%s", sessionIdSignature, encodeToString(salt), userId, expTimeStr, encodeToString(hmac)), nil
}

func (mlc *AuthMagicLinkController) VerifySessionId(sessionId string) (user *AuthUserRecord, err error) {
	if !strings.HasPrefix(sessionId, sessionIdSignature) {
		return nil, ErrInvalidSessionId
	}
	sessionId = sessionId[len(sessionIdSignature):]
	parts := strings.Split(sessionId, "-")
	if len(parts) != 4 {
		return nil, ErrInvalidSessionId
	}

	salt, err := decodeFromString(parts[0])
	if err != nil {
		return nil, ErrInvalidSessionId
	}
	userId, err := ulid.ParseStrict(parts[1])
	if err != nil {
		return nil, ErrInvalidSessionId
	}
	expTime, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, ErrInvalidSessionId
	}
	if expTime < int(time.Now().Unix()) {
		return nil, ErrExpiredSessionId
	}
	hmac1, err := decodeFromString(parts[3])
	if err != nil {
		return nil, ErrInvalidSessionId
	}
	hmac2 := mlc.makeHMAC(slices.Concat(salt, []byte{0}, userId.Bytes(), []byte{0}, []byte(parts[2])))
	if !hmac.Equal(hmac1, hmac2) {
		return nil, ErrBrokenSessionId
	}
	// Now we're sure the session Id is validated, so the userId should be valid
	return mlc.db.GetUserById(userId)
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

func NewAuthUserRecord(email string) (aur *AuthUserRecord, err error) {
	now := time.Now()
	aur = &AuthUserRecord{
		ID:              ulid.Make(),
		Email:           NormalizeEmail(email),
		Enabled:         true,
		FirstLoginTime:  now,
		RecentLoginTime: now,
		CustomData:      nil,
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
	return fmt.Sprintf("_%s_%s", aur.ID.String(), aur.Email)
}

// Binary-string encoding
func encodeToString(b []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

func decodeFromString(s string) ([]byte, error) {
	s = s + strings.Repeat("=", 8-(len(s)%8))
	return base32.StdEncoding.DecodeString(s)
}
