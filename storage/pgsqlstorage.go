package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/ivoras/gomagiclink"
)

type PgSQLStorage struct {
	db        *sql.DB
	tableName string
}

// NewPgSQLStorage creates a PgSQLStorage instance, with PostgreSQL-flavoured SQL.
// This storage engine will use a single table in the SQL database,
// that needs to have these fields:
//
//	id		Some type that can store the 16-byte UUID, either as a text field, or a dedicated type (PostgreSQL has a plugin for the native UUID type)
//	email	text
//	data	A type that can accept a long JSON string, either as text, or as a dedicated type (PostgreSQL has a native JSONB field)
//
// This table needs to be maintained entirely by the caller, including indexes.
// A unique index on the `id` field, and another unique index on the `email` field are highly recommended.
func NewPgSQLStorage(db *sql.DB, tableName string) (st *PgSQLStorage, err error) {
	return &PgSQLStorage{
		db:        db,
		tableName: tableName,
	}, nil
}

func (st *PgSQLStorage) StoreUser(user *gomagiclink.AuthUserRecord) (err error) {
	userJson, err := json.Marshal(user)
	if err != nil {
		return
	}
	// It's a race condition, but UPSERT isn't standardised across common databases
	if !st.UserExistsByEmail(user.Email) {
		_, err = st.db.Exec(fmt.Sprintf("INSERT INTO %s (id, email, data) VALUES ($1, $2, $3)", st.tableName), user.ID.String(), user.Email, string(userJson))
	} else {
		_, err = st.db.Exec(fmt.Sprintf("UPDATE %s SET data=$1 WHERE id=$2", st.tableName), string(userJson), user.ID.String())
	}

	return
}

func (st *PgSQLStorage) GetUserById(id uuid.UUID) (user *gomagiclink.AuthUserRecord, err error) {
	var userJson string
	err = st.db.QueryRow(fmt.Sprintf("SELECT data FROM %s WHERE id=$1", st.tableName), id.String()).Scan(&userJson)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, gomagiclink.ErrUserNotFound
		}
		return
	}

	user = &gomagiclink.AuthUserRecord{}
	err = json.Unmarshal([]byte(userJson), user)
	return
}

func (st *PgSQLStorage) GetUserByEmail(email string) (user *gomagiclink.AuthUserRecord, err error) {
	var userJson string
	err = st.db.QueryRow(fmt.Sprintf("SELECT data FROM %s WHERE email=$1", st.tableName), gomagiclink.NormalizeEmail(email)).Scan(&userJson)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, gomagiclink.ErrUserNotFound
		}
		return
	}

	user = &gomagiclink.AuthUserRecord{}
	err = json.Unmarshal([]byte(userJson), user)
	return
}

func (st *PgSQLStorage) UserExistsByEmail(email string) (exists bool) {
	var count int
	err := st.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE email=$1", st.tableName), gomagiclink.NormalizeEmail(email)).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (st *PgSQLStorage) GetUserCount() (n int, err error) {
	err = st.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", st.tableName)).Scan(&n)
	return
}

func (st *PgSQLStorage) UsersExist() (exist bool, err error) {
	err = st.db.QueryRow(fmt.Sprintf("SELECT EXISTS (SELECT * FROM %s)", st.tableName)).Scan(&exist)
	return
}
