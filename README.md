## Binary Diffing and Marimo Rust

Marimo notebook analysis of CVE-2025-53766 GDI+ Remote Code Execution Vulnerability using the Rust Diff plugin for Binary Ninja https://github.com/meerkatone/rust_diff

## Clone the repo
git clone https://github.com/meerkatone/patch_chewsday_cve_2025_53766.git

## Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

## Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

## Setup venv and Marimo
uv venv --python 3.13

source .venv/bin/activate

cd binary_diffing_and_marimo_rust

uv pip install marimo

## Launch the notebook
marimo edit ./CVE_2025_53766_diffing.py

The notebook may ask you to install the required dependencies via uv
