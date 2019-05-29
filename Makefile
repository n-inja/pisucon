all:
	go build -o app

setup:
	go get -u .

run:
	env ISUCONP_DB_PASSWORD='password' go run app.go

img:
	env ISUCONP_DB_PASSWORD='password' POST_EXTRACT='y' go run app.go
