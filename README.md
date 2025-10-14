# Alpen Labs Rust Workspace Template

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/rust-template/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/rust-template/actions)
[![docs](https://img.shields.io/badge/docs-docs.rs-orange)](https://docs.rs/rust-template)

This repo is a template for easy setup of a Rust workspace project within
[`AlpenLabs` GitHub organization](https://github.com/alpenlabs).
If you are looking for the single crate template, you can find it at
[`alpenlabs/rust-template](https://github.com/alpenlabs/rust-template).

- It comes with a preconfigured `.justfile` for common tasks.
- Licensing is taken care of, with dual MIT-Apache 2.0 licenses.
- Continuous Integration is already set up with the common GitHub actions jobs
hardened with [`zizmor`](https://docs.zizmor.sh).
- Dependabot is enabled to automatically bump Rust and GitHub actions dependencies monthly.
- There are 1 pull request template and 2 issues templates for bug reports and feature requests.
- Proper lints for code maintainability are added to `Cargo.toml`.
- If you need to publish crates to `crates.io`, you can use the `just publish` command,
  and it will be automatically triggered by CI on every new tag release.
  You just need to add a crates.io token to the `CARGO_REGISTRY_TOKEN` repository secret variable.

This template has a lot of `CHANGEME` placeholders that you should replace with your own values.
Please do a repository-wide search and replace all occurrences of `CHANGEME` with your own values.

## Settings and Branch Protection Rules

Note that settings and branch protection rules are not ported over to new repositories
created using templates.
Hence, you'll need to change settings and add branch protection rules manually.
Here's a suggestion for branch protection rules for the default branch,
i.e. `main`:

```json
{
  "id": 2405180,
  "name": "Main Branch Protection",
  "target": "branch",
  "source_type": "Repository",
  "source": "alpenlabs/NAME",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "exclude": [],
      "include": [
        "~DEFAULT_BRANCH"
      ]
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "automatic_copilot_code_review_enabled": false,
        "allowed_merge_methods": [
          "merge",
          "squash",
          "rebase"
        ]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {
            "context": "Check that lints passed",
            "integration_id": 15368
          },
          {
            "context": "Check that unit tests pass",
            "integration_id": 15368
          }
        ]
      }
    },
    {
      "type": "merge_queue",
      "parameters": {
        "merge_method": "SQUASH",
        "max_entries_to_build": 5,
        "min_entries_to_merge": 1,
        "max_entries_to_merge": 5,
        "min_entries_to_merge_wait_minutes": 5,
        "grouping_strategy": "ALLGREEN",
        "check_response_timeout_minutes": 60
      }
    }
  ],
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "pull_request"
    }
  ]
}
```
## Features

- Feature 1
- Feature 2

## Usage

```rust
// How to use the library/binary.
```

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
