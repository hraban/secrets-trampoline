# Copyright © 2023  Hraban Luyat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

{
  inputs = { };

  outputs = {
    self
    , nixpkgs
  }: {
    # Module to allow darwin hosts to get the timezone name as a string without
    # a password. Insanity but ok. Separate module because it affects different
    # parts of the system and I want all that code grouped together.
    darwinModules.default = { pkgs, config, lib, ... }:
      let
        program = { name, pkgs, config, lib, ... }: {
          options = with lib; with types; {
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
      in {
        options = with lib; with types; {
          secrets-trampoline = {
            programs = mkOption {
              type = attrsOf (submodule program);
              description = mdDoc "Programs that can be launched with a secret";
              default = {};
            };
            secrets = mkOption {
              type = attrsOf anything;
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
              type = raw;
              description = mdDoc "Read a secret to pass to nix-darwin.

This is a function that accepts the secret name as an argument, and returns a
shell command (as a string) which, when executed, will fetch that secret somehow
e.g. from keychain or 1Password.

Be careful to escape values as you deem necessary. Since the string is executed
as a bash command, it can also just be the path to a derivation which contains a
script doing the real work.

The shell command will be executed at `nix-darwin switch` time.";
              example = literalExpression "name: ''\${pkgs._1password}/bin/op read \"op://Personal/Nix/\${name}\"''";
            };
          };
        };
        config =
          let
            sw = config.secrets-trampoline;
            # make this sudo’able
            makeBinaryWrapper = pkgs.writeShellScript "makeBinaryWrapper" ''
              source "${pkgs.makeBinaryWrapper}/nix-support/setup-hook"
              # I don't understand why, but this is necessary?
              set +eu
              makeBinaryWrapper "''${@}"
            '';
          in {
          system.activationScripts.preUserActivation.text = lib.concatMapStringsSep "\n" (program: ''
            (
              set -euo pipefail
              umask 077
              d="$(mktemp -d)"
              (
                cd "$d"
                declare -a args
                ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: ''
                  secret="$(${sw.secretReader (sw.secrets.${value})})"
                  args+=("--set" ${lib.escapeShellArg name} "$secret")
                '') program.secrets)}
                # Yes this briefly exposes the secret through the argv!
                sudo ${makeBinaryWrapper} ${lib.getExe program.drv} wrapper "''${args[@]}"
                ${lib.concatMapStringsSep "\n" (user: ''
                  sudo /bin/chmod +a "user:"${lib.escapeShellArg user}":allow:execute" wrapper
                '') program.users}
                sudo mkdir -p /var/run/secrets-trampolines
                sudo chown root /var/run/secrets-trampolines
                sudo chmod 755 /var/run/secrets-trampolines
                sudo mv wrapper /var/run/secrets-trampolines/${lib.escapeShellArg (lib.getName program.drv)}
              )
              rm -rf "$d"
            )
          '') (builtins.attrValues sw.programs);
        };
      };
  };
}
