# credlens — verification entry points (see CLAUDE.md)

.PHONY: corpus test lint

# Assemble the pinned eval corpus into corpus/servers/ (verified against manifest tree_sha256)
corpus:
	uv run python scripts/fetch_corpus.py

test:
	uv run pytest

lint:
	uv run ruff check .
