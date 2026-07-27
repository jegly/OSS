"""Every name a module uses must be bound somewhere in that module.

This exists because `distro.install_hint(...)` was added to window.py without
importing `distro`. Python raises NameError only when the line runs, and that
line runs inside a GTK callback — where GLib swallows the exception and the
window simply hangs showing nothing. It shipped in a .deb and broke the app for
anyone missing an optional package, which on a stock Ubuntu desktop is everyone.

Deliberately over-approximate: a name bound *anywhere* in the file counts as
bound, so nothing here reasons about scope. That gives up on catching subtler
shadowing bugs and in exchange produces no false positives, which is the only
way a check like this survives contact with a real codebase.
"""

from __future__ import annotations

import ast
import builtins
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "ossgui"

#: Injected by the runtime rather than bound in the source.
_IMPLICIT = {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__builtins__"}


def _bound_names(tree: ast.AST) -> set[str]:
    """Every name this module binds, by any means, at any depth."""
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, ast.MatchAs) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    return bound


def _loaded_names(tree: ast.AST) -> dict[str, int]:
    """Every name this module reads, mapped to the first line that reads it."""
    loaded: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loaded.setdefault(node.id, node.lineno)
    return loaded


class TestNoUndefinedNames(unittest.TestCase):
    def test_every_module(self) -> None:
        known = set(dir(builtins)) | _IMPLICIT
        problems: list[str] = []

        for path in sorted(SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            bound = _bound_names(tree) | known
            for name, lineno in sorted(_loaded_names(tree).items()):
                if name not in bound:
                    problems.append(
                        f"{path.relative_to(SRC.parent.parent)}:{lineno}: "
                        f"{name!r} is used but never imported or defined"
                    )

        self.assertEqual(problems, [], "\n" + "\n".join(problems))


class TestHelperScriptToo(unittest.TestCase):
    def test_helper_and_launcher(self) -> None:
        """The two entry points are not importable modules, so glob misses them."""
        root = SRC.parent.parent
        known = set(dir(builtins)) | _IMPLICIT
        problems: list[str] = []

        for path in (root / "helper" / "oss-helper", root / "oss"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            bound = _bound_names(tree) | known
            for name, lineno in sorted(_loaded_names(tree).items()):
                if name not in bound:
                    problems.append(f"{path.name}:{lineno}: {name!r} is never bound")

        self.assertEqual(problems, [], "\n" + "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
