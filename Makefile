include .devkit/runtime/devkit.mk

.PHONY: gate_crate_dag gate_banned_crates gate_unsafe_and_clippy gate_no_internal_leaks report_loc_stats

ifeq ($(strip $(value app)$(value package)),)
check: gate_no_internal_leaks gate_crate_dag gate_banned_crates gate_unsafe_and_clippy report_loc_stats
endif

# Both Cargo policy tests run in the same offline container and reuse its target.
gate_crate_dag gate_banned_crates: test/packages/efferian-authz

gate_unsafe_and_clippy: $(call devkit_targets,check) test/packages/efferian-platform

gate_no_internal_leaks:
	@sh scripts/gate_no_internal_leaks.sh
	@sh scripts/test_no_internal_leaks.sh

report_loc_stats:
	-@sh scripts/report_loc_stats.sh
