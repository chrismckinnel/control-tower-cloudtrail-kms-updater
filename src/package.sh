#!/usr/bin/env bash
 
# https://stackoverflow.com/a/246128
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
 
pushd $SCRIPT_DIRECTORY > /dev/null
 
rm -rf .package securityhub_enabler.zip
 
zip cloudtrail_updater.zip cloudtrail_updater.py
 
popd > /dev/null
