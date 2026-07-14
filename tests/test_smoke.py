import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Parser

import credlens


def test_version():
    assert credlens.__version__


def test_grammars_load_and_parse():
    """Every grammar in the parsing spine loads and parses a trivial program."""
    cases = [
        (tree_sitter_typescript.language_typescript(), b"const k: string = process.env.API_KEY;"),
        (tree_sitter_javascript.language(), b"const k = process.env.API_KEY;"),
        (tree_sitter_python.language(), b"import os\nk = os.environ['API_KEY']\n"),
    ]
    for lang_ptr, source in cases:
        parser = Parser(Language(lang_ptr))
        tree = parser.parse(source)
        assert not tree.root_node.has_error
