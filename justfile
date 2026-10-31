default:
    @just --list

# Install the toolchains mise pins, then the git hooks
setup:
    mise install
    just hooks

# Install the lefthook git hooks (pre-commit, pre-push, commit-msg)
hooks:
    lefthook install

# Build the 2fa binary into ./bin
build:
    go build -o bin/2fa .

# Run the unit suite with the race detector
test:
    go test -race -count=1 ./...

# Run the unit suite with a coverage report (a report for humans, not a gate)
test-cover:
    go test -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -func=coverage.out | tail -1
    @echo "HTML report: go tool cover -html=coverage.out"

# Run golangci-lint over the repository
lint:
    golangci-lint run ./...

# Auto-fix what the linters can fix, then report what is left
lint-fix:
    golangci-lint run --fix ./...

# Verify go.mod/go.sum are tidy (CI runs this; a dirty tree fails the build)
tidy-check:
    #!/usr/bin/env bash
    set -euo pipefail
    # $TMPDIR is not set on every Linux runner, so do not rely on it.
    backup=$(mktemp -d)
    trap 'rm -rf "$backup"' EXIT
    cp go.mod "$backup/go.mod" && cp go.sum "$backup/go.sum"
    go mod tidy
    if ! diff -q "$backup/go.mod" go.mod >/dev/null || ! diff -q "$backup/go.sum" go.sum >/dev/null; then
        echo "go.mod/go.sum are not tidy; run 'go mod tidy' and commit the result" >&2
        exit 1
    fi
    echo "go.mod and go.sum are tidy"

# Mutation testing asks what coverage cannot: not "did a test execute this line?"
# but "would any test have noticed if it behaved differently?".
#
# --config is passed explicitly rather than left to discovery, so a wrong path
# is a hard "Could not read config file" rather than a silent default-config run.
#
# The threshold defaults to 0 because the package has no meaningful tests yet;
# raise it to just below the measured score as tests are added.
#
# Mutation-test the package; fails below the threshold (exit code 4)
mutate threshold="0":
    mutago --config=.mutago.yaml --min-msi={{threshold}} --quiet --no-diffs .

# Mutation-test the package and show the diff for every surviving mutant
mutate-report:
    mutago --config=.mutago.yaml --html-output .
    @echo "wrote mutago-report.html"

# Format and lint the Markdown, then check the prose. vale is advisory here:
# its local verdict depends on whatever global config the developer has, and a
# gate that answers differently per machine is not one worth failing a build on.
docs:
    rumdl fmt README.md
    rumdl check README.md
    -vale README.md

# --strict-collection is the flag that matters here. Without it, a workflow
# zizmor cannot parse produces a WARN and is skipped, so a broken file reads as
# a clean audit. A duplicate `name:` key once hid this repository's entire CI
# workflow from the audit that way.
#
# Lint the workflows for validity (actionlint) and for safety (zizmor)
actions:
    actionlint
    zizmor --strict-collection .

# Run the govulncheck vulnerability scanner
vulncheck:
    govulncheck ./...

# Every gate CI runs on a pull request
check: tidy-check lint test vulncheck actions
