# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))

import subprocess, sys, os

script_dir = os.path.dirname(os.path.abspath(__file__))


def abspath(relpath):
    return os.path.abspath(os.path.join(script_dir, relpath))


# -- Project information -----------------------------------------------------

project = "Sinker"
copyright = "2023, widberg"
author = "widberg"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autosectionlabel",
    "breathe",
]

breathe_projects = {
    "sinker": abspath("../build/doxygen/xml/")
}

for breathe_project in breathe_projects:
    os.makedirs(breathe_projects[breathe_project], exist_ok=True)

breathe_default_project = "sinker"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

html_theme_options = {
    "collapse_navigation": False,
    "style_nav_header_background": "#1e5696",
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_css_files = [
    "css/custom.css",
]


def run_doxygen(app):
    """Run the doxygen command"""
    try:
        retcode = subprocess.call("doxygen", cwd=abspath(".."))
        if retcode:
            sys.stderr.write("doxygen terminated by signal %s" % retcode)
            sys.exit(1)
    except OSError as e:
        sys.stderr.write("doxygen execution failed: %s" % e)
        sys.exit(1)


def setup(app):
    # Add hook for building doxygen when needed
    app.connect("builder-inited", run_doxygen)
