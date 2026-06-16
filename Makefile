BINARY := tanya
MODULE := github.com/fanzybear/tanya

.PHONY: build install tidy vet check clean

build:
	go build -ldflags="-s -w" -o $(BINARY) .

install: build
	@echo "Installing $(BINARY) to /usr/local/bin/"
	sudo cp $(BINARY) /usr/local/bin/$(BINARY)

tidy:
	go mod tidy

vet:
	go vet ./...

check: vet build

clean:
	rm -f $(BINARY)
