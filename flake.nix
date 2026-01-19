{
  inputs = {
    # FlakeHub nixpkgs: "0" tracks the current stable nixpkgs channel on FlakeHub
    nixpkgs.url = "https://flakehub.com/f/DeterminateSystems/nixpkgs-weekly/0.tar.gz";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nodejs_24
            bun
            # pnpm
            gemini-cli
            # effectively an alias to pn
            # (pkgs.writeShellScriptBin "pn" ''
            #   exec pnpm "$@"
            # '')
          ];

          shellHook = ''
            echo "Nix dev shell activated"
            echo "Node:  $(node --version 2>/dev/null || echo 'not found')"
            echo "Bun:  $(bun --version 2>/dev/null || echo 'not found')"
          '';
        };
      }
    );
}
