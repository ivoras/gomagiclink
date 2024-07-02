all: cmd/demo/demo
	echo OK

cmd/demo/demo:
	cd cmd/demo && go build -o demo
