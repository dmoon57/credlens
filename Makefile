# credlens — verification entry points (see CLAUDE.md)

.PHONY: corpus test lint

# Assemble the pinned eval corpus into corpus/servers/ (verified against manifest tree_sha256)
corpus:
	uv run python scripts/fetch_corpus.py

# Generate the labeled-by-construction mutation corpus into corpus/mutations/
mutations:
	uv run python scripts/plant_mutations.py

# Run the eval harness against the real-server labels + mutation corpus
eval:
	uv run python -m credlens.eval

# CI entry point: assemble inputs, verify mutation reproducibility, gate on the floor
eval-ci:
	uv run python scripts/fetch_corpus.py
	uv run python scripts/plant_mutations.py --check
	uv run python -m credlens.eval --gate

test:
	uv run pytest

lint:
	uv run ruff check .
