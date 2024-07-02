package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/ivoras/gomagiclink"
	"github.com/ivoras/gomagiclink/storage"
)

var consoleReader *bufio.Reader

func readLine(prompt string) (s string) {
	fmt.Print(prompt)
	s, err := consoleReader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	return
}

func main() {
	consoleReader = bufio.NewReader(os.Stdin)

	fsStorage, err := storage.NewFileSystemStorage(".")
	if err != nil {
		panic(err)
	}

	magicLinkController, err := gomagiclink.NewAuthMagicLinkController(
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "),
		time.Hour,
		time.Hour*24,
		fsStorage,
	)
	if err != nil {
		panic(err)
	}

	email := readLine("Input e-mail address: ")

	challenge, err := magicLinkController.GenerateChallenge(email)
	if err != nil {
		if err == gomagiclink.ErrUserAlreadyExists {
			fmt.Println("User already exists")
		}
	}

	var user *gomagiclink.AuthUserRecord
	if challenge != "" {
		fmt.Println("Challenge: ", challenge)

		user, err = magicLinkController.VerifyChallenge(challenge)
		if err != nil {
			panic(err)
		}
	} else {
		user, err = magicLinkController.GetUserByEmail(email)
		if err != nil {
			panic(err)
		}
	}

	user.CustomData = "data"

	err = magicLinkController.StoreUser(user)
	if err != nil {
		panic(err)
	}

	sessionId, err := magicLinkController.GenerateSessionId(user)
	if err != nil {
		panic(err)
	}
	fmt.Println("Session Id:", sessionId)

	user2, err := magicLinkController.VerifySessionId(sessionId)
	if err != nil {
		panic(err)
	}
	if user.ID != user2.ID {
		panic("user.ID != user2.ID")
	}

	if (user2.CustomData).(string) != "data" {
		panic("CustomData mismatch")
	}

	t0 := time.Now()
	for i := 0; i < 10000; i++ {
		_, err = magicLinkController.VerifySessionId(sessionId)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("10k session verifications took", time.Now().Sub(t0))

}
