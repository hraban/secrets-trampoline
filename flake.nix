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

  outputs = { self }: {
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
        # There has to be a better way to do this? types.addCheck don’t work
        secret = with lib; with types; (attrsOf anything) // {
          check = x: ((attrsOf anything).check x) && builtins.hasAttr "type" x;
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
              example = literalExpression "{ \"1Password\" = { name } : ''\${pkgs._1password}/bin/op read \"op://Personal/Nix/\${name}\"''; }";
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
                ${pkgs._1password}/bin/op read "op://${vault}/${item}/${entry}"
              '';
            };
            sw = config.secrets-trampoline;
            # make this sudo’able
            makeBinaryWrapper = pkgs.writeShellScript "makeBinaryWrapper" ''
              source "${pkgs.makeBinaryWrapper}/nix-support/setup-hook"
              # I don't understand why, but this is necessary?
              set +eu
              makeBinaryWrapper "''${@}"
            '';
          in {
          system.activationScripts.preUserActivation.text = ''
            sudo rm -rf ${lib.escapeShellArg sw.directory}
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
                    secret = sw.secrets.${value};
                    reader = (defaultReaders // sw.secretReader).${secret.type};
                    args = builtins.removeAttrs secret ["type"];
                  in ''
                    secret="$(${reader args})"
                    args+=("--set" ${lib.escapeShellArg name} "$secret")
                  '') program.secrets)}
                # Yes this briefly exposes the secret through the argv!
                sudo ${makeBinaryWrapper} ${lib.getExe program.drv} wrapper "''${args[@]}"
                ${lib.concatMapStringsSep "\n" (user: ''
                  sudo /bin/chmod +a "user:"${lib.escapeShellArg user}":allow:execute" wrapper
                '') program.users}
                sudo mkdir -p ${lib.escapeShellArg sw.directory}
                sudo chown root ${lib.escapeShellArg sw.directory}
                sudo chmod 755 ${lib.escapeShellArg sw.directory}
                sudo mv wrapper ${lib.escapeShellArg sw.directory}/${lib.escapeShellArg name}
              )
              rm -rf "$d"
            )
          '') sw.programs);
        };
      };
  };
}
