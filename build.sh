#!/bin/bash

pkg=github.com/jamesliu96/pont/cmd/pts
app=pts
tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
ldflags="-X main.app=$app -X main.gitTag=$tag -X main.gitRev=$rev"
out=public/$app.wasm
echo "# $pkg $tag $rev" 1>&2

printf "removing \"$out\" ... "
rm -rf $out \
  && echo "SUCCEEDED" \
  || echo "FAILED"
ldflags="$ldflags -s -w"
os=js
arch=wasm
printf "building \"$out\" ... "
CGO_ENABLED=0 \
GOOS=$os GOARCH=$arch \
  go build -trimpath -ldflags="$ldflags" -o $out $pkg \
    && echo "SUCCEEDED" \
    || echo "FAILED"