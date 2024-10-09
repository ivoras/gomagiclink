# Description

This is a simple demo web app that asks the user for their e-mail address, simulates sending them
an e-mail messages with the magic link (the demo app writes the magic link to the console), and
maintains a simple local database of users.

It implements a complete login and logout cycle.

# Notes

This example uses SQLite to store user information. The gomagiclink library itself doesn't require any 
storage (information is stored JWT-style in the browser / front-end app), but it's convenient to have
some kind of local user management.

