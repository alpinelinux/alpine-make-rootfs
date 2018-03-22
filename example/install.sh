#!/bin/sh

# Copy some file from the repository root to the rootfs.
install -D -m 755 examples/hello_world.rb /app/hello_world.rb

# Install some dev packages and gem mailcatcher.
apk add --no-progress -t .make build-base ruby-dev sqlite-dev
gem install --no-document mailcatcher

# Clean-up dev packages.
apk del --no-progress .make
