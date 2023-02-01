#/usr/bin/env sh
cat<<EOF
BUILD_TAG ${GIT_COMMIT:-$(git describe --tags --long --always)}
EOF