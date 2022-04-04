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
import os
import sys

sys.path.insert(0, os.path.abspath("../"))

# Get version info from dissect.cobaltstrike._version
try:
    from dissect.cobaltstrike._version import version

    version, _, _ = version.partition("+")
    release = version
except ModuleNotFoundError:
    release = version = "unknown"

# -- Project information -----------------------------------------------------

project = "dissect.cobaltstrike"
copyright = "2022, NCC Group / Fox-IT"
author = "NCC Group / Fox-IT"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.viewcode",
    "sphinx.ext.githubpages",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "IPython.sphinxext.ipython_console_highlighting",
    "IPython.sphinxext.ipython_directive",
    "sphinx_copybutton",
    "autoapi.extension",
    "sphinx_argparse_cli",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "*/_version.py"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

pygments_style = "friendly"

autodoc_member_order = "bysource"

autoapi_dirs = ["../dissect"]
autoapi_ignore = ["*/_version.py"]
autoapi_python_use_implicit_namespaces = True
autoapi_generate_api_docs = True
autoapi_root = "autoapi"
autoapi_add_toctree_entry = False
autoapi_include_inheritance_graphs = False
autoapi_python_class_content = "class"
autoapi_template_dir = "_templates/_autoapi_templates"
autoapi_keep_files = False

copybutton_remove_prompts = True
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
