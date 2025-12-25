# Copyright © 2023–2025  Hraban Luyat
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
  inputs.flake-parts.url = "flake-parts";

  # Only used for treefmt
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  inputs.treefmt-nix.url = "github:numtide/treefmt-nix";
  inputs.systems.url = "systems";

  outputs =
    {
      self,
      treefmt-nix,
      flake-parts,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { ... }:
      {
        systems = import inputs.systems;
        imports = [
          inputs.treefmt-nix.flakeModule
          ({
            flake.darwinModules.default = import ./secrets-trampoline.nix;
            perSystem =
              { ... }:
              {
                treefmt = import ./treefmt.nix { };
              };
          })
        ];
      }
    );
}
