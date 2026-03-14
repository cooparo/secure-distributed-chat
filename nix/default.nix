{
  buildGoModule,
  lib,

  go,
  sqlc,
}:
# Check https://nixos.org/manual/nixpkgs/stable/#sec-language-go
buildGoModule {
  pname = "grat";
  version = "0.8.0";

  meta = with lib; {
    description = "P2P chat, written in Go";
    homepage = "https://github.com/cooparo/secure-distributed-chat";
    license = licenses.mit;
  };

  subPackages = [
    "cmd/gratcli"
    "cmd/gratserver"
  ];

  src = ../.;
  vendorHash = "sha256-xtdp8kFpYur5tuIr6xbuB2joqrvTnpIirBMjOzR7DWY=";

  nativeBuildInputs = [
    go
    sqlc
  ];

  postBuild = "echo Hello from post build";
  postInstall = "echo Hello from post install";
}
