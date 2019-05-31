all:
	go build -o app

setup:
	go get -u .

test:
	env ISUCONP_DB_PASSWORD='password' PPROF='y' GOGC='200' go run app.go index.qtpl.go posts.qtpl.go

run:
	env ISUCONP_DB_PASSWORD='password' GOGC='200' go run app.go index.qtpl.go posts.qtpl.go

img:
	env ISUCONP_DB_PASSWORD='password' POST_EXTRACT='y' go run app.go index.qtpl.go posts.qtpl.go
