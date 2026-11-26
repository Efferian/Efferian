# Managed component registration.
DEVKIT_REGISTERED_APPS := cli hub node
DEVKIT_REGISTERED_PACKAGES := efferian-authz efferian-client efferian-platform efferian-protocol
DEVKIT_DESKTOP_APPS := 
setup-cli: setup-rust-workspace
check-cli: check/packages/efferian-client build/packages/efferian-client check/packages/efferian-platform build/packages/efferian-platform check/packages/efferian-protocol build/packages/efferian-protocol
test-cli: build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
build-cli: build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
dev-cli: build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
setup-hub: setup-rust-workspace
check-hub: check/packages/efferian-authz build/packages/efferian-authz check/packages/efferian-client build/packages/efferian-client check/packages/efferian-platform build/packages/efferian-platform check/packages/efferian-protocol build/packages/efferian-protocol
test-hub: build/packages/efferian-authz build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
build-hub: build/packages/efferian-authz build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
dev-hub: build/packages/efferian-authz build/packages/efferian-client build/packages/efferian-platform build/packages/efferian-protocol
setup-node: setup-rust-workspace
check-node: check/packages/efferian-platform build/packages/efferian-platform check/packages/efferian-protocol build/packages/efferian-protocol
test-node: build/packages/efferian-platform build/packages/efferian-protocol
build-node: build/packages/efferian-platform build/packages/efferian-protocol
dev-node: build/packages/efferian-platform build/packages/efferian-protocol
setup/packages/efferian-authz: setup-rust-workspace
check/packages/efferian-authz: check/packages/efferian-protocol build/packages/efferian-protocol
test/packages/efferian-authz: build/packages/efferian-protocol
build/packages/efferian-authz: build/packages/efferian-protocol
setup/packages/efferian-client: setup-rust-workspace
check/packages/efferian-client: check/packages/efferian-protocol build/packages/efferian-protocol
test/packages/efferian-client: build/packages/efferian-protocol
build/packages/efferian-client: build/packages/efferian-protocol
setup/packages/efferian-platform: setup-rust-workspace
setup/packages/efferian-protocol: setup-rust-workspace
DEVKIT_EXPECTED_PLAN := 466d4ef9e71eeacc902269785dffd11dcc860a7bf49cfd5f51357f224fb8e70e
