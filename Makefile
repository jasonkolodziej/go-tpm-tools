# Generate is hi
# Ref: https://github.com/opencontainers/umoci/blob/master/Makefile
.PHONY: generate
generate:
	$(BUF) generate

# Used to produce vendor directory
# if other proto files need access to a vendor's proto file
go_gen_vendor:
	[ -d "./vendor" ] && echo "Directory ./vendor exists." || \
		echo "NOTICE: Directory ./vendor does not exist... trying set up" && \
		go mod vendor
# Buf build linting
.PHONY: lint
lint:
	$(BUF) lint

.PHONY: break-against
break-against:
	$(BUF) breaking --against 'https://github.com/johanbrandhorst/grpc-gateway-boilerplate.git#branch=master'

# Display well known types
list-known-types:
	$(BUF) build --exclude-source-info -o -#format=json | jq '.file[] | .package' | sort | uniq | head

# List all Proto files, changes such as 'excludes' can be made here
list-files:
	$(BUF) ls-files ./proto

# Remote Inputs - We're listing the files from a git archive,
#  so you'll notice that the result includes the start/petapis/ prefix,
#  which is the relative filepath from the root of the git archive.
# buf ls-files git://github.com/bufbuild/buf-tour.git#branch=main,subdir=start/petapis

BUF_VERSION:=0.43.2
BUF ?= buf
# install installs all the necessary Buf build
.PHONY: install
install: go_plug_install
# Install go-based buf plugins
go_plug_install:
	go install \
		google.golang.org/protobuf/cmd/protoc-gen-go

buf_install: $(BUF)
	curl -sSL \
    	"https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(shell uname -s)-$(shell uname -m)" \
    	-o "$(shell go env GOPATH)/bin/buf" && \
  	chmod +x "$(shell go env GOPATH)/bin/buf"

# Buf build dependency updates
.PHONY: bufdepup
bufdepup:
	$(BUF) beta mod update

# steps to do before building anything
.PHONY: prelim
prelim: go_build_prelim

# Remove go's vendor folder for dev testing
go_build_prelim:
	[ -d "./vendor" ] && \
		echo " buf gen should have completed.. Directory ./vendor exists.. removing for test purposes" \
		&& rm -r ./vendor ./api/gogoproto