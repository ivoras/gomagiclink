package main

// This is an example web app for the gomagiclink module, implementing the magic link login workflow.

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ivoras/gomagiclink"
	"github.com/ivoras/gomagiclink/storage"
	_ "github.com/mattn/go-sqlite3"
)

const cookieName = "MLCOOKIE"
const cookieDurationSeconds = 3600
const wwwListen = "localhost:8003"

var mlink *gomagiclink.AuthMagicLinkController

func main() {
	db, err := sql.Open("sqlite3", "./magiclink.db")
	if err != nil {
		panic(err)
	}
	mlStorage, err := storage.NewPgSQLStorage(db, "magiclink")
	if err != nil {
		panic(err)
	}
	mlink, err = gomagiclink.NewAuthMagicLinkController(
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit."), // Our secret key
		time.Hour,    // User challenge (i.e. magic link) expiration
		time.Hour*24, // Session ID (i.e. cookied) expiration
		mlStorage,    // Storage engine for user data
	)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", wwwRoot)
	http.HandleFunc("/login", wwwLogin)
	http.HandleFunc("/challenge", wwwChallenge)
	http.HandleFunc("/verify", wwwVerifyChallenge)
	http.HandleFunc("/logout", wwwLogout)

	log.Println("Listening on", wwwListen)
	log.Println(http.ListenAndServe(wwwListen, Logger(os.Stderr, http.DefaultServeMux)))
}

type Page struct {
	FileName string
	Title    string
	tpl      *template.Template
}

func loadPage(FileName, Title string) (p *Page, err error) {
	tpl, err := template.ParseFiles(fmt.Sprintf("templates/%s", FileName))
	if err != nil {
		return
	}
	return &Page{
		FileName: FileName,
		Title:    Title,
		tpl:      tpl,
	}, nil
}

func wwwError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	w.Write([]byte(msg))
	log.Println("ERROR:", msg)
}

// Shows the app, or redirects to /login if the HTTP cookie isn't set or the session id is invalid
func wwwRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		if err != http.ErrNoCookie {
			wwwError(w, http.StatusInternalServerError, "Cookie error")
			return
		}
	}
	if cookie == nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, err := mlink.VerifySessionId(cookie.Value)
	if err != nil {
		// Remove the cookie
		http.SetCookie(w, &http.Cookie{
			Name:   cookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		wwwError(w, http.StatusBadRequest, "Can't parse session cookie: "+err.Error())
		return
	}

	// This is the actual web app. We're just incrementing the counter here and making
	// use of the CustomData feature.

	user.CustomData = user.CustomData.(float64) + 1
	err = mlink.StoreUser(user)
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Can't store user record")
		return
	}

	p, err := loadPage("index.html", "Session counter")
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Can't load index template")
		return
	}

	p.tpl.Execute(w, struct {
		Title   string
		Counter int
	}{
		Title:   p.Title,
		Counter: int(user.CustomData.(float64)),
	})
}

// Just shows the login form
func wwwLogin(w http.ResponseWriter, r *http.Request) {
	p, err := loadPage("login.html", "Magic Link Login")
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Can't load login template")
	}
	p.tpl.Execute(w, struct {
		Title string
	}{
		Title: p.Title,
	})
}

// Accepts an email address sent by the login form, creates the magic link challenge for it,
// and sends it to the user. In this demo, it just shows the magic link to the user.
func wwwChallenge(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Error parsing form")
		return
	}
	email := r.Form.Get("email")
	log.Println(email)
	if email == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	challenge, err := mlink.GenerateChallenge(email)
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Error generating challenge")
		return
	}

	url := fmt.Sprintf("http://%s/verify?challenge=%s", wwwListen, url.QueryEscape(challenge))
	fmt.Println("Open this URL in the browser to start verification:", url)

	p, err := loadPage("challenge.html", "Challenge issued")
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Can't load challenge template")
	}
	p.tpl.Execute(w, struct {
		Title     string
		Email     string
		Challenge string
		Url       string
	}{
		Title:     p.Title,
		Email:     email,
		Challenge: challenge,
		Url:       url,
	})
}

// Verifies the challenge present in the magic link sent to the user's e-mail address.
// If it's ok, this endpoint:
//   - Creates or retrieves the AuthUserRecord,
//   - Generates the session id
//   - Creates a HTTP cookie and adds the session ID to it
func wwwVerifyChallenge(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")
	if challenge == "" {
		log.Println("Empty challenge")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, err := mlink.VerifyChallenge(challenge)
	if err != nil {
		switch err {
		case gomagiclink.ErrBrokenChallenge:
			wwwError(w, http.StatusBadRequest, "Broken challenge")
		case gomagiclink.ErrInvalidChallenge:
			wwwError(w, http.StatusBadRequest, "Invalid challenge")
		case gomagiclink.ErrExpiredChallenge:
			wwwError(w, http.StatusBadRequest, "Expired challenge")
		default:
			wwwError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	if user.CustomData == nil {
		user.CustomData = float64(0) // CustomData goes through JSON, so all numbers are float64
	}
	if count, err := mlink.GetUserCount(); err == nil && count == 0 { // 1st user, make it an admin
		user.AccessLevel = 1000
	}
	err = mlink.StoreUser(user)
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Error storing user")
		return
	}
	sessionId, err := mlink.GenerateSessionId(user)
	if err != nil {
		wwwError(w, http.StatusInternalServerError, "Error generating session id")
		return
	}
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    sessionId,
		Path:     "/",
		MaxAge:   cookieDurationSeconds,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Just deletes the HTTP cookie.
func wwwLogout(w http.ResponseWriter, r *http.Request) {
	// Remove the cookie
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
