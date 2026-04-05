BINARY  := spire-plugin-alnumid-credential-composer
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty)

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: all build test clean

all: build

build:
	$(foreach PLATFORM,$(PLATFORMS), \
		$(eval OS   := $(word 1,$(subst /, ,$(PLATFORM)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(PLATFORM)))) \
		$(eval EXT  := $(if $(filter windows,$(OS)),.exe,)) \
		$(eval OUT  := $(DIST)/$(BINARY)_$(OS)_$(ARCH)$(EXT)) \
		GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags="-X main.version=$(VERSION)" -o $(OUT) . && \
		echo "built $(OUT)" ; \
	)

test:
	go test -v -count=1 ./...

clean:
	rm -rf $(DIST)
