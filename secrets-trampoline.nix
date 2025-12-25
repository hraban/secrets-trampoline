{ pkgs, config, lib, ... }:
let
  program = { name, pkgs, config, lib, ... }: {
    options = with lib; with types; {
      enable = mkOption {
        type = bool;
        default = true;
        example = false;
      };
      drv = mkOption {
        type = package;
        description = mdDoc "Inner package to call with the secret as an envvar";
        example = literalExpression "pkgs.writeShellScriptBin \"run-foo\" ''echo \"I can read secret $MY_SECRET\"''";
      };
      # TODO: Allow all, or group, etc
      users = mkOption {
        type = listOf str;
        description = mdDoc "The users who have access to this program without password";
      };
      secrets = mkOption {
        type = attrsOf str;
        default = {};
        description = mdDoc "Secrets to pass into the program.";
        example = {
          MY_SECRET = "my-secret";
        };
      };
    };
  };
  secret = with lib; with types; types.addCheck (attrsOf anything) (
    x: ((attrsOf anything).check x) && builtins.hasAttr "type" x
  );
in {
  options = with lib; with types; {
    secrets-trampoline = {
      enable = lib.mkEnableOption "Secrets trampolines management in darwin";
      programs = mkOption {
        type = attrsOf (submodule program);
        description = mdDoc "Programs that can be launched with a secret";
        default = {};
      };
      secrets = mkOption {
        type = attrsOf secret;
        default = {};
        description = mdDoc ''
          A single secret specification.

          The value is passed verbatim as an argument to the
          secretReader, for which see docs.
        '';
        example = {
          my-secret = "api key 1";
        };
      };
      secretReader = mkOption {
        type = attrsOf (functionTo str);
        description = mdDoc ''Read a secret to pass to nix-darwin.

This is a function that accepts the secret name as an argument, and returns a
shell command (as a string) which, when executed, will fetch that secret somehow
e.g. from keychain or 1Password.

Be careful to escape values as you deem necessary. Since the string is executed
as a bash command, it can also just be the path to a derivation which contains a
script doing the real work.

The shell command will be executed at `nix-darwin switch` time.

By default, a 1Password reader is provided.
'';
        default = {};
        example = literalExpression "{ \"1Password\" = { name } : ''\${pkgs._1password-cli}/bin/op read \"op://Personal/Nix/\${name}\"''; }";
      };
      directory = mkOption {
        type = str;
        default = "/usr/local/secrets-trampolines";
        description = mdDoc "Directory on local filesystem in which to store the trampolines";
      };
    };
  };
  config =
    let
      defaultReaders = {
        "1Password" = { vault, item, entry }: ''
          sudo -u ${lib.escapeShellArg config.system.primaryUser} --set-home \
            ${pkgs._1password-cli}/bin/op read "op://${vault}/${item}/${entry}"
        '';
      };
      cfg = config.secrets-trampoline;
    in lib.mkIf cfg.enable {
    system.activationScripts.preActivation.text = ''
      rm -rf ${lib.escapeShellArg cfg.directory}
    '' + lib.concatStringsSep "\n" (lib.mapAttrsToList (name: program: ''
      (
        set -euo pipefail
        umask 077
        d="$(mktemp -d)"
        (
          cd "$d"
          declare -a args
          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value:
            let
              secret = cfg.secrets.${value};
              reader = (defaultReaders // cfg.secretReader).${secret.type};
              args = builtins.removeAttrs secret ["type"];
            in ''
              secret="$(${reader args})"
              # shellcheck disable=SC2030,SC2031
              args+=("--set" ${lib.escapeShellArg name} "$secret")
            '') program.secrets)}
          # Yes this briefly exposes the secret through the argv!
          (
            # shellcheck disable=SC1091
            source "${pkgs.makeBinaryWrapper}/nix-support/setup-hook"
            # I don't understand why, but this is necessary?
            set +eu
            makeBinaryWrapper ${lib.getExe program.drv} wrapper "''${args[@]}"
          )
          ${lib.concatMapStringsSep "\n" (user: ''
            # shellcheck disable=SC2140
            /bin/chmod +a "user:"${lib.escapeShellArg user}":allow:execute" wrapper
          '') program.users}
          mkdir -p ${lib.escapeShellArg cfg.directory}
          chown root ${lib.escapeShellArg cfg.directory}
          chmod 755 ${lib.escapeShellArg cfg.directory}
          mv wrapper ${lib.escapeShellArg cfg.directory}/${lib.escapeShellArg name}
        )
        rm -rf "$d"
      )
    '') (lib.filterAttrs (_: v: v.enable) cfg.programs));
  };
}
