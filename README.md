# user-auth-service
User authentication service created with Go. It is a personal project of mine to get practice writing Go and a useful reference for
any future projects that may require user authentication.

For production projects, I recommend using other securely built third-party solutions that solve
this problem.

Built using Go and MongoDB. Hashing of passwords done with bcrypt library, and authorization is done via JWTs.

# Prerequisites
In order to use this service, you will need to install MongoDB locally. [Here](https://docs.mongodb.com/manual/installation/) is a link to installing MongoDB Community Edition for your OS.

I recommend you create a `.env` file in your root directory to define a `SECRET_KEY` variable, which is used for signing the generated JWTs.

# Getting Started
To run the service, navigate to the root directory and run:
- `go run service.go`
