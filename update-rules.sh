#!/usr/bin/env sh

echo 'updating sigma rules started'
git clone https://github.com/SigmaHQ/sigma.git
rm -r ./rules/
mkdir ./rules/
mv ./sigma/rules/linux/ ./rules/
rm -r ./sigma/
echo 'updating sigma rules done'
