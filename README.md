# gomagiclink

Magic Link auth framework for Go

# Workflows

* Construct an `AuthUserDatabase`
* Collect user e-mail (web form, etc)
* Check if the user exists in the `AuthUserDatabase`. If yes, retrieve it
* Construct `NewAuthUserRecord()`, store it in the `AuthUserDatabase`
* Generate a string challenge (magic cookie) with `GenerateChallenge()`, send to user's e-mail
* When the user returns the challenge, verify it with `VerifyChallenge()` and you'll receive an AuthRecord with a session cookie

actually no, we don't want to store sessions cookies; we want them to behave like JWTs and be verified on every request

* Store this session cookie in a `AuthRecordDatabase`
* Send this session cookie to the browser/client, e.g. in an actual HTTP cookie
* On each request, call