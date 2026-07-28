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


class TestEntryPointsPreferTheTreeTheyLiveIn(unittest.TestCase):
    """Both entry points must load the ossgui beside them, not the installed one.

    This is the trap that cost a whole debugging session: with an old .deb
    installed, `./oss` and the dev helper both put /usr/share/oss at the front
    of sys.path, so every fix under test ran as the *installed* code and
    appeared to do nothing at all. The launcher must append; the helper must
    choose by its own location, never from the environment — it runs as root
    under pkexec, where a caller-chosen import path is a caller-chosen payload.
    """

    def source(self, name: str) -> str:
        root = SRC.parent.parent
        path = root / name
        return path.read_text(encoding="utf-8")

    def test_launcher_appends_the_installed_path(self) -> None:
        text = self.source("oss")
        self.assertIn('sys.path.append("/usr/share/oss")', text)
        self.assertNotIn('sys.path.insert(0, "/usr/share/oss")', text)

    def test_helper_picks_its_own_tree_over_the_installed_one(self) -> None:
        text = self.source("helper/oss-helper")
        # Unconditionally fronting the installed copy is the bug; the helper
        # must look for a sibling src/ first.
        self.assertNotRegex(
            text, r"^sys\.path\.insert\(0, \"/usr/share/oss\"\)",
        )
        self.assertIn("_DEV_SRC", text)
        self.assertIn('sys.path.insert(0, "/usr/share/oss")', text)

    def test_the_helper_never_reads_the_environment_to_choose(self) -> None:
        """pkexec sanitises the environment, and root must not trust it anyway."""
        import ast

        tree = ast.parse(self.source("helper/oss-helper"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = getattr(node.func, "attr", "")
            value = getattr(getattr(node.func, "value", None), "id", "")
            if value == "os" and target in ("getenv", "environ"):
                self.fail("the helper must not choose its import path from the environment")

    def test_the_dev_helper_resolves_to_the_dev_tree(self) -> None:
        """Executed for real: the condition must hold on this checkout."""
        root = SRC.parent.parent
        helper = root / "helper" / "oss-helper"
        dev_src = helper.resolve().parent.parent / "src"
        self.assertTrue(
            (dev_src / "ossgui" / "__init__.py").is_file(),
            "the dev helper would fall through to the installed copy",
        )
        self.assertEqual(dev_src / "ossgui", SRC)


if __name__ == "__main__":
    unittest.main()
