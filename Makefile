BINDIR := bin

CMDS := $(filter-out %_test.go,$(notdir $(wildcard cmd/*)))

.PHONY: all
all: $(CMDS)


$(CMDS):
	go build -buildmode=pie -trimpath -o $(BINDIR)/$@ ./cmd/$@

.PHONY: clean
clean:
	rm -rf $(BINDIR)
