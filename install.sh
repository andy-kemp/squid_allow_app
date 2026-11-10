#!/bin/bash
# PAW Proxy Pilot installer. Run on Ubuntu Server 24.04 LTS:  sudo ./install.sh   (see --help)
exec bash "$(dirname "$(readlink -f "$0")")/deploy/install.sh" "$@"
