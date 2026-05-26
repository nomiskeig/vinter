{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs_old.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs_old,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgs_old = import nixpkgs_old { inherit system; };

      overrides = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml));
      libPath =
        with pkgs;
        lib.makeLibraryPath [
          # load external libraries that you need in your rust project here
        ];

    in
    {
      devShells.${system}.default = pkgs.mkShell rec {
        packages =
          with pkgs_old;
          [
            stdenv.cc
            bash
            clang
            rustup
            rustc
            cargo
            pkg-config
            zlib
            glib
            autoconf
            automake
            chrpath
            libtool
            libelf
            curl
            llvm
            protobuf3_17
            protobufc
            gcc
            capstone
            flex
            bison
            zip
            glibc
            glibc.static
          ]
          ++ [
            pkgs.python3
            pkgs.python313Packages.pycparser
            pkgs.python313Packages.pip
          ];
        RUSTC_VERSION = overrides.toolchain.channel;
        LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];
        shellHook = ''
             export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
             export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
          if [ ! -d .venv ]; then
             python -m venv .venv
           fi

           source .venv/bin/activate
        '';

        # Add precompiled library to rustc search path
        RUSTFLAGS = (
          builtins.map (a: "-L ${a}/lib") [
            # add libraries here (e.g. pkgs.libvmi)
          ]
        );

        LD_LIBRARY_PATH = libPath;

        # Add glibc, clang, glib, and other headers to bindgen search path
        BINDGEN_EXTRA_CLANG_ARGS =
          # Includes normal include path
          (builtins.map (a: ''-I"${a}/include"'') [
            # add dev libraries here (e.g. pkgs.libvmi.dev)
            pkgs.glibc.dev
          ])
          # Includes with special directory paths
          ++ [
            ''-I"${pkgs.llvmPackages_latest.libclang.lib}/lib/clang/${pkgs.llvmPackages_latest.libclang.version}/include"''
            ''-I"${pkgs.glib.dev}/include/glib-2.0"''
            "-I${pkgs.glib.out}/lib/glib-2.0/include/"
          ];

      };

    };
}
