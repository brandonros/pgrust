{
  description = "pgrust PostgreSQL 18.3 test environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/38e3bfd71b104d00dbc7159340294a20534cd624";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
      environment = system:
        let
          pkgs = import nixpkgs { inherit system; };
          postgres = pkgs.postgresql_18;
        in
        assert postgres.version == "18.3";
        {
          inherit pkgs postgres;
          shell = pkgs.mkShell ({
            packages = [ postgres postgres.dev pkgs.python3 pkgs.awscli2 pkgs.pkg-config ];
            PG_VERSION = postgres.version;
            PG_BIN = "${postgres}/bin";
            PG_TESTS = "${postgres.dev}/lib/pgxs/src/test";
            # Use upstream sources, before Nixpkgs patches its test schedule.
            PG_TEST_SOURCE = "${postgres.src}/src/test";
            PGRUST_PGSHAREDIR = "${postgres}/share/postgresql";
            PGRUST_TZDIR = "${pkgs.tzdata}/share/zoneinfo";
          } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
            # pgrust loads ICU at runtime; match initdb's collation library.
            DYLD_LIBRARY_PATH = "${pkgs.icu}/lib";
          } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            LD_LIBRARY_PATH = "${pkgs.icu}/lib";
          });
        };
    in
    {
      packages = forEachSystem (system: {
        default = (environment system).postgres;
      });
      devShells = forEachSystem (system: {
        default = (environment system).shell;
      });
    };
}
