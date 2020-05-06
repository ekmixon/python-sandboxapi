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
sys.path.insert(0, os.path.abspath('../..'))


# -- Project information -----------------------------------------------------

project = 'sandboxapi'
copyright = '2019, InQuest, LLC'
author = 'Chris Morrow'

# The full version, including alpha/beta/rc tags
release = '2.0.0rc0'

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx_autodoc_typehints',
    'm2r',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
source_suffix = ['.rst', '.md']

# The encoding of source files.
# source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
# if on_rtd:
#     html_theme = 'sphinx_rtd_theme'
# else:
#     html_theme = 'alabaster'

html_theme = 'alabaster'

if html_theme == 'alabaster':
    html_theme_options = {
        'fixed_sidebar': 'true',
        'logo': 'sandboxapi.png',
        'font_family': '"Proxima Nova", "Helvetica Neue", Helvetica, Arial, sans-serif',
        'head_font_family': '"Proxima Nova", "Helvetica Neue", Helvetica, Arial, sans-serif',
        'logo_name': 'true',
        'description': 'Minimal, consistent Python API for building integrations with malware sandboxes.',
        'github_user': 'InQuest',
        'github_repo': 'python-sandboxapi',
        'github_type': 'star',
        'show_powered_by': 'false',
        'page_width': 'auto',
        'sidebar_width': '320px',
        'gray_1': '#23272d',
        'gray_2': '#f7f9fc',
        'gray_3': '#fefeff',
        'pink_1': '#ff796e',
        'pink_2': '#e12a26',
        'body_text': '#1f292f',
        'footer_text': '#919396',
        'link': '#e03f26',
        'link_hover': '#e03f26',
        'sidebar_search_button': '#ccc',
        'narrow_sidebar_bg': '#f0f2f5',
        'narrow_sidebar_link': '#1f292f'
    }

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

html_sidebars = {
    '**': [
        'about.html',
        'localtoc.html',
        'relations.html',
        'links.html',
        'searchbox.html',
    ]
}