# gomagiclink

Magic Link auth framework for Go

# Design decisions

* We don't write down information about the user until they verify the challenge
* We don't write down session information at all, but verify the cookie JWT-style
* We allow the app to attach arbitrary data about a user

# Workflows

## Registration / Login

* Construct an `AuthUserDatabase`
* Construct an `AuthMagicLinkController`
* Collect user e-mail (web form, etc)
* Check if the user exists with `GetUserByEmail()`
* If not, generate a string challenge (magic cookie) with `GenerateChallenge()`, send to user's e-mail
* Verify the challenge with `VerifyChallenge()`. If successful, it will return an `UserAuthRecord`
* Optionally attach custom user data to the `CustomData` field of the record.
* Store the `AuthUserRecord` in the `AuthUserDatabase`

## Session

* Generate a session ID with `GenerateSessionId()`, send to browser, e.g. as a HTTP cookie, or a Bearer token
* Each time the browser sends back the session ID, verify it with `VerifySessionId()`. It will return an `AuthUserRecord` if successful.
