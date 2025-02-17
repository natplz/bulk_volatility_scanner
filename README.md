Bulk Volatility Scanner
=======================

Run targeted Volatility plugins on one or more memory images, and save the results for analysis.

#### Syntax:
- `python3 bulk_vol.py --output_dir=/desired/output/directory MemoryImage1.raw MemoryImage2.raw`


#### Positional arguments:
-  image_files     &nbsp; Path(s) to memory image(s). Each positional argument will be treated as a separate memory image.


#### Optional arguments:
-  --output_dir    &nbsp; Path to directory where output will be saved. Default is './'
-  --invocation    &nbsp; Path to Volatility2 command. Default is 'vol.py'
-  --profile       &nbsp; Provide a valid profile and KDBG offset to bypass profile auto-detection.
-  --kdbg          &nbsp; Provide a valid profile and KDBG offset to bypass profile auto-detection. Example of valid KDBG offset: 0x8273cb78 
-  --readlist      &nbsp; List of plugins to run a memory image against. If not specified, plugins will be selected automatically.
-  -h, --help      &nbsp; Show this help message and exit


#### Notes:
- If a provided output directory folder does not exist, the folder will be created.
- If no profile or KDBG offset is provided, profile auto-detection will be run (using Volatility's imageinfo plugin). The first profile returned will be used.
