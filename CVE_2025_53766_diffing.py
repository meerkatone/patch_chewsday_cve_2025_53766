import marimo

__generated_with = "0.18.0"
app = marimo.App(width="full")


@app.cell(hide_code=True)
def _():
    import marimo as mo
    import plotly.express as px
    import polars as pl
    import quak
    import altair as alt
    import duckdb
    import pandas as pd
    import json
    from pathlib import Path
    import pyarrow as pa
    return Path, alt, duckdb, json, mo, pd


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h1>Patch Chewsday Analysis: CVE-2025-53766 GDI+ Remote Code Execution Vulnerability</h1>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/meme.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>CVE Workflow</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    - Search the MITRE CVE site for Microsoft Windows 11, and pick a CVE that looks interesting from the last three months:
        - https://www.cve.org/CVERecord/SearchResults?query=microsoft+windows+11
        - Review the CVE description

    - Check the MSRC link:
        - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53766
        - Find the patched build version number
        - Check the KB article:
            - https://support.microsoft.com/en-gb/topic/august-12-2025-kb5063878-os-build-26100-4946-e4b87262-75c8-4fef-9df7-4a18099ee294
        - Check the binaries that have been updated for the provided list in the KB:
            - https://go.microsoft.com/fwlink/?linkid=2331814
            - gdiplus.dll appears in the list

    - Search Winbindex for the likely vulnerable binary - in this case it's most likley gdiplus.dll based on the CVE description and KB manifest:
        - https://winbindex.m417z.com/?file=gdiplus.dll
        - Find the patched dll 10.0.26100.4946:
            - https://msdl.microsoft.com/download/symbols/gdiplus.dll/3C2E90F01df000/gdiplus.dll
        - Find the N-1 dll 10.0.26100.4768:
            - https://msdl.microsoft.com/download/symbols/gdiplus.dll/654171D41de000/gdiplus.dll

    - Analyse the dlls in Binary Ninja
    - Use the Rust Diff plugin
    - Look for functions that are not a 100% match
    - Extract the BinExport features for both dlls, and compare them in BinDiff
    - Comapare the results with the Binary Ninja Rust Diff plugin
        - Look for the vulnerability, and the patch
        - Ask AI: "You're absolutely right!"
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/cve_search.png", width=800, height=600)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/cve.png", width=700, height=400)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/kb.png", width=800, height=600)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/gdiplus.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/4768.png", width=900, height=550)
    return


@app.cell
def _(mo):
    mo.image(src="./screenshots/4946.png", width=900, height=550)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>BinDiff Results</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/bindiff.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>BinDiff Results in Binary Ninja</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/bindiff_binary_ninja.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Setup Dataframe</h2>
    """)
    return


@app.cell(hide_code=True)
def _(Path, json, pd):
    def load_and_process_json(json_file_path, Path, json, pd):
        with open(json_file_path, 'r') as f:
            data = json.load(f)

        # Extract filenames from metadata
        binary_a = Path(data['metadata']['binary_a']).name
        binary_b = Path(data['metadata']['binary_b']).name

        # Create separate columns for each result
        processed_results = []
        for result in data['results']:
            processed_result = {
                'binary_a': binary_a,
                'binary_b': binary_b,
                'function_a_name': result['function_a']['name'],
                'function_a_address': f"0x{result['function_a']['address']:x}",
                'function_a_size': result['function_a']['size'],
                'function_b_name': result['function_b']['name'],
                'function_b_address': f"0x{result['function_b']['address']:x}",
                'function_b_size': result['function_b']['size'],
                'similarity': result['similarity'],
                'similarity_rounded': round(result['similarity'], 4),
                'confidence': result['confidence'],
                'match_type': result['match_type']
            }
            processed_results.append(processed_result)

        df = pd.DataFrame(processed_results)
        return df, binary_a, binary_b

    # Usage:
    json_file_path = "./CVE_2025_53766.json"
    df, binary1, binary2 = load_and_process_json(json_file_path, Path, json, pd)
    df
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Binary Ninja Diff Plugin</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.image(src="./screenshots/rustdiff.png")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Binary Ninja Pseudo C Decompilation </h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.hstack([
        mo.vstack([
            mo.md("<div style='text-align: left'>Vulnerable EpScanBitmap::NextBuffer</div>"),
            mo.image(src="./screenshots/vuln.png", width=700, height=400)
        ]),
        mo.vstack([
            mo.md("<div style='text-align: left'>Patched EpScanBitmap::NextBuffer</div>"),
            mo.image(src="./screenshots/patched.png", width=700, height=400)
        ])
    ])
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ```text

    Vulnerable Code

    void* rcx = (int64_t)*(uint32_t*)((char*)this + 0x508) * 0x278;

    Multiplies an unchecked integer by 0x278 without bounds validation.
    No verification that rcx offset stays within allocated buffer.
    Can cause out-of-bounds memory access.

    __________________________________________________________________________________

    Patched Code

    Added feature flag with bounds checking.

    if (*(uint32_t*)((char*)this + 8) + r14
            > *(uint32_t*)(*(uint64_t*)((char*)this + 0x510) + 4)) {
        RtlLogUnexpectedCodepath(&var_48);
    }

    Adds bounds validation, and checks if (current_position + r14) exceeds the max buffer size.
    Clamps r14 to the available space: r14 = rcx_4 if exceeds limit.

    Prevents unbounded writes to EpAlphaBlender::Blend
    ```
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Patch Concerns</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    - Potential for the bug to resurface if there is regression in the code base
    - Similar bugs may be in other parts of GDI+ or in other core components of Windows
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Next Steps</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    - Create PoC to help test our assumptions
    - Check for similar bugs in GDI+ via program analysis
    - Check for similar bugs across the core windows binaries via program analysis - file format parsers are the gift that keep giving
    - Fuzzing
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Query Similarity < 0.99</h2>
    """)
    return


@app.cell(hide_code=True)
def _(duckdb, mo):
    query1 = """
    SELECT function_a_name, function_b_name, similarity
    FROM df
    WHERE similarity < 0.99
    ORDER BY similarity ASC
    LIMIT 30
    """

    sim = duckdb.query(query1).to_df()
    mo.ui.dataframe(sim)
    return (sim,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Similarity Slider</h2>
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    similarity_slider = mo.ui.slider(
        start=0.600,
        stop=1.000,
        step=0.010,
        value=0.990,
        label="Similarity Threshold")
    similarity_slider
    return (similarity_slider,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Functions with Similarity Below Slider Threshold (Bar Chart)</h2>
    """)
    return


@app.cell(hide_code=True)
def _(alt, mo, sim, similarity_slider):
    df_filtered_slider = sim[sim["similarity"] < similarity_slider.value]

    # Build the chart
    chart_obj = alt.Chart(df_filtered_slider).mark_bar().encode(
        x=alt.X("function_a_name:N", title="Function Name").scale(zero=False),
        y=alt.Y("similarity:Q", title="Similarity").scale(zero=False),
        color=alt.Color('similarity:Q', scale=alt.Scale(scheme='viridis')),
        tooltip=["function_a_name", "function_b_name", "similarity"]
    ).properties(
        width=700,
        height=400,
        title="Functions with Similarity Below Slider Threshold"
        ).configure_axisX(
        labelAngle=45
    )

    # Display the chart
    mo.ui.altair_chart(chart_obj)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Query Function Name Matches</h2>
    """)
    return


@app.cell(hide_code=True)
def _(duckdb, mo):
    query5 = """
    SELECT function_a_name, function_b_name, similarity
    FROM df
    WHERE function_a_name == function_b_name
    AND similarity < 0.99
    ORDER BY similarity DESC
    LIMIT 20

    """

    clashes = duckdb.query(query5).to_df()
    mo.ui.dataframe(clashes)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>Query Best Matches</h2>
    """)
    return


@app.cell(hide_code=True)
def _(duckdb, mo):
    query_best_matches = """
    WITH ranked_matches AS (
        SELECT *,
               ROW_NUMBER() OVER (PARTITION BY function_a_name ORDER BY similarity DESC) AS rank1,
               ROW_NUMBER() OVER (PARTITION BY function_b_name ORDER BY similarity DESC) AS rank2
        FROM df
        WHERE similarity <= 0.99
    )
    SELECT function_a_address, function_a_name, function_b_address, function_b_name, similarity
    FROM ranked_matches
    WHERE rank1 = 1 AND rank2 = 1
    ORDER BY similarity DESC
    """

    best_matches = duckdb.query(query_best_matches).to_df()
    mo.ui.dataframe(best_matches)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    <h2>References</h2>
     - CVE-2025-53766: https://www.cve.org/CVERecord?id=CVE-2025-53766
     - GDI+ Remote Code Execution Vulnerability: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063
     - gdiplus.dll - Winbindex: https://winbindex.m417z.com/?file=gdiplus.dll
    """)
    return


if __name__ == "__main__":
    app.run()
