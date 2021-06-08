Bulk Volatility Scanner
=======================

Run targeted Volatility plugins on one or more memory images and save the results for analysis.

Syntax: `python3 bulk_vol.py --output_dir=/desired/output/directory MemoryImage1.raw MemoryImage2.raw

positional arguments:
  image_files     Path to Memory Image(s)
  output_dir      Path to Output Directory

optional arguments:
  -h, --help  show this help message and exit

The first suggested profile will be automatically selected.
All available plugins will be selected for the suggested profile.
If the output directory does not exist, it will be created.
The output files with follow a $plugin_$filename format.
