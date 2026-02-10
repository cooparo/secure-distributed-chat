{
  description = "Secure Distributed Chat";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      flake-parts,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        # "aarch64-linux"
        # "x86_64-darwin"
        # "aarch64-darwin"
      ];

      perSystem =
        { pkgs, self', ... }:
        {
          # Package build
          packages.default = pkgs.callPackage ./nix/default.nix { };

          # Executables
          apps."gratcli" = {
            type = "app";
            program = "${self'.packages.default}/bin/gratcli";
            meta.description = "CLI to interact with the chat";
          };
          apps."gratserver" = {
            type = "app";
            program = "${self'.packages.default}/bin/gratserver";
            meta.description = "Chat daemon running in the background";
          };

          # Development environment
          devShells.default = import ./nix/shell.nix { inherit pkgs; };
        };
    };
}
