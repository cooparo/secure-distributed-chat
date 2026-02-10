{ pkgs }:
pkgs.mkShell {
  packages = with pkgs; [
    go
    golangci-lint
    gotools
    # TODO: check this tools
    # go-junit-report
    # gocover-cobertura
    # go-task
    # goreleaser

    sqlc
  ];
}
