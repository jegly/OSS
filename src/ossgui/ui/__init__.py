"""Everything that imports ``gi`` lives here.

Keeping the GTK layer in its own package is what lets the privileged helper
import the catalogue, renderer and apply logic without pulling in a UI toolkit.
"""
