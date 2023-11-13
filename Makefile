all: init generate

init:
	@echo "Making ChopChopGo..."
#add special compiler options beyond -w later,
#maybe use a packer or some sort.
generate:
	go build -ldflags "-w" .

clean:
	@echo "done."

update-rules:
	./update-rules.sh

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-w" .

