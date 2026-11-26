# Working on Efferian

- Run commands from the root with GNU Make. Start a new checkout with `make setup` online, then `make doctor`. Use `make check`, `make test` and `make build` before submitting changes. CI runs these same targets.
- Keep the four libraries under `packages/` and the three executables under `apps/`. Follow the dependency table in the README. Build each application on its own so Cargo keeps the Node process feature and Hub OpenAPI feature isolated.
- Keep dependencies in the root workspace manifest and inherit them in their consumers. Use the pinned Rust environment for dependency changes, for example `make exec toolchain=rust write=1 network=bridge command='cargo update -p reqwest'`. Run `make sync` and `make setup` afterwards. Commit the root lockfile and regenerated metadata together.
- Manage the pinned `@docouno/devkit` environment through the root Make targets. Use `make help` for component and toolchain selectors. Extend repository checks in the root Makefile.
- Keep production Rust safe. Document every unsafe block in `efferian-platform` with its safety invariant. Keep code, tests and contributor documentation in English.
