bulk_volatility_scanner
=======================

Run all available Volatility plugins on a target image file.

Syntax:

python bulk_vol.py image_files output_directory

positional arguments:
  image_files           Path to Memory Image(s)
  output_directory      Path to Output Directory

optional arguments:
  -h, --help  show this help message and exit

The first suggested profile will be automatically selected.
All available plugins will be selected for the suggested profile.
If the output directory does not exist, it will be created.
The output files with follow a $plugin_$filename format.
