# 🛠 Development Guide: crtforge

This guide is intended for developers who want to contribute to the `crtforge` codebase.

## 💻 Prerequisites

Before you start developing, ensure you have the following installed:

- **Go (Golang):** Version `1.21` or higher is recommended.
- **OpenSSL:** Must be installed and available in your `PATH`.
- **Git:** To manage the codebase.

## 🏗 Building from Source

You can build the `crtforge` binary locally with custom versioning information.

Run the following command in the root directory of the project:

```bash
# Get current version and commit ID
version=$(git describe --tags --abbrev=0)
commitId=$(git --no-pager log -1 --oneline | awk '{print $1}')

# Build the binary with injected version metadata
go build -ldflags "-X crtforge/cmd.version=$version -X crtforge/cmd.commitId=$commitId" -o crtforge -v .
```

The `-ldflags` argument injects the current Git tag and commit SHA into the `cmd.version` and `cmd.commitId` variables, which is useful for `--version` flags.

## 🧪 Testing

### Running Tests

Currently, the project uses Go's built-in testing framework. Run all tests using:

```bash
go test ./...
```

## 🎨 Code Standards

- **Formatting:** Always run `go fmt ./...` before committing.
- **Logging:** Use `github.com/sirupsen/logrus` for all logging. Avoid using `fmt.Println` for debugging/info messages.
- **Error Handling:** Follow standard Go error handling patterns (check errors immediately and return/log them).
- **Command Structure:** All CLI command logic is centralized in `cmd/`. Business logic resides in `cmd/services/`.

## 🚀 Contribution Workflow

To maintain a clean history and ensure issue tracking, please follow this workflow:

### 1. Prepare the Issue
- Before starting work, find the relevant issue on GitHub.
- Comment on the issue stating that you are working on it (e.g., "In progress").

### 2. Create a Dedicated Branch
Always create a new branch for your work. Do not commit directly to `master`.
- **For new features:** `feature/feature-name`
- **For bug fixes:** `bugfix/issue-number-description`
- **For critical production fixes:** `hotfix/description`

### 3. Develop and Test
- Implement your changes.
- **Crucial:** Ensure you run `go test ./...` to verify your changes haven't broken existing functionality.

### 4. Submit a Pull Request (PR)
When your work is ready for review:
- Push your branch to GitHub.
- Open a Pull Request (PR) against the `master` branch.
- **Link the Issue:** In your PR description, include the text `Closes #ID` (where `ID` is the issue number). This automatically closes the issue when the PR is merged.
- **Include Context:** Provide a clear description of what was changed and why.

---
*Created for crtforge documentation.*
