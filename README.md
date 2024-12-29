[![Go Reference](https://pkg.go.dev/badge/github.com/ivoras/gomagiclink.svg)](https://pkg.go.dev/github.com/ivoras/gomagiclink)

# gomagiclink

Magic Link authentication framework for Go. The idea is to avoid asking the user for the password every
time they login, and send them a "magic link" to their e-mail address. Once they confirm the login by
clicking the link, the user is considered logged in. This has the advantage of not handling user
passwords at all, and the disadvantage that if their e-mail account is compromised, this will cascade
to services dependant on the e-mail account, such as ones implementing the magic link login.

This package implements the core part of this process, by generating a cryptographically safe magic link
challenge and a session id (useful for web cookies). To keep the process safe, you need to maintain
the security of the secret key, passed to the `NewAuthMagicLinkController()` function.

[API reference](https://pkg.go.dev/github.com/ivoras/gomagiclink)

# Design decisions

* We don't write down information about the user until they verify the challenge
* We don't write down session information at all, but verify the cookie JWT-style
* We allow the app to attach arbitrary data about a user, and store it with the user record
* We allow easy implementation of different data stores

# Workflows

See these examples for more info:

* [the web app example](cmd/webdemo/)
* [the CLI example](cmd/demo/)

## Registration / Login

1. Construct an `AuthUserDatabase` - there are examples for SQL databases and a plain file system storage in this repo
2. Construct an `AuthMagicLinkController` - this is the code that does crypto and login
3. Collect user e-mail (with a web form, etc)
4. Generate a challenge string (magic cookie) with `GenerateChallenge()`, construct a link with it and send it to user's e-mail
5. Verify the challenge with `VerifyChallenge()`. If successful, it will return an `UserAuthRecord`
6. Optionally attach custom user data to the `CustomData` field of the record and store the `AuthUserRecord` with `StoreUser()`. Note that this data will be stored and retrieved as JSON, so the `CustomData` needs to be of a type that can survive a round-trip through JSON. For example, `int`s will be returned as `float64`s.

By the nature of this login system, unique users are represented by unique e-mail addresses.

## Session

After a magic link chanllenge has been completed, you can optionally create a session id to store in a cookie.

1. Generate a session ID with `GenerateSessionId()`, send it to the browser, e.g. as a HTTP cookie, or a Bearer token
2. Each time the browser sends back the session ID, verify it with `VerifySessionId()`. It will return an `AuthUserRecord` if successful. Inspect the `CustomData` field if you've set it before.

The `AuthUserRecord` is a structure where you can attach arbitrary information, such as information about the user's profile, or an app-specific user ID if you don't like using UUIDs that this library uses.

## Sending e-mail

Configuring an e-mail server, etc. is waaaay out of scope for this package, but
[here's a good e-mail library for Go](https://github.com/jordan-wright/email).
