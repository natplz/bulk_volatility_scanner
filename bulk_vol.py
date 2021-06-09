import argparse
import logging
import os
import re
import multiprocessing
import subprocess
import sys
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SUPPORTED_PROFILES = [
	"VistaSP0x64",
	"VistaSP0x86",
	"VistaSP1x64",
	"VistaSP1x86",
	"VistaSP2x64",
	"VistaSP2x86",
	"Win10x64",
	"Win10x64_10240_17770",
	"Win10x64_10586",
	"Win10x64_14393",
	"Win10x64_15063",
	"Win10x64_16299",
	"Win10x64_17134",
	"Win10x64_17763",
	"Win10x64_18362",
	"Win10x64_19041",
	"Win10x86",
	"Win10x86_10240_17770",
	"Win10x86_10586",
	"Win10x86_14393",
	"Win10x86_15063",
	"Win10x86_16299",
	"Win10x86_17134",
	"Win10x86_17763",
	"Win10x86_18362",
	"Win10x86_19041",
	"Win2003SP0x86",
	"Win2003SP1x64",
	"Win2003SP1x86",
	"Win2003SP2x64",
	"Win2003SP2x86",
	"Win2008R2SP0x64",
	"Win2008R2SP1x64",
	"Win2008R2SP1x64_23418",
	"Win2008R2SP1x64_24000",
	"Win2008SP1x64",
	"Win2008SP1x86",
	"Win2008SP2x64",
	"Win2008SP2x86",
	"Win2012R2x64",
	"Win2012R2x64_18340",
	"Win2012x64",
	"Win2016x64_14393",
	"Win7SP0x64",
	"Win7SP0x86",
	"Win7SP1x64",
	"Win7SP1x64_23418",
	"Win7SP1x64_24000",
	"Win7SP1x86",
	"Win7SP1x86_23418",
	"Win7SP1x86_24000",
	"Win81U1x64",
	"Win81U1x86",
	"Win8SP0x64",
	"Win8SP0x86",
	"Win8SP1x64",
	"Win8SP1x64_18340",
	"Win8SP1x86",
	"WinXPSP1x64",
	"WinXPSP2x64",
	"WinXPSP2x86",
	"WinXPSP3x86"
]

BASE_PLUGINS = [
	# Step 1: Identify Rogue Processes
	'malprocfind',
	'pslist',
	'psscan',
	'pstree',

	# Step 2: Analyze process DLLs and Handles
	'cmdline',
	'dlllist',
	'getsids',
	'handles',
	'mutantscan',
	'svcscan',

	# Step 4: Look for evidence of code injection
	'hollowfind',
	'ldrmodules',
	'malfind',

	# Step 5: Check for a rootkit
	'apihooks',
	'driverirp',
	'idt',
	'modscan',
	'psxview',
	'ssdt',

	# Step 6: Dump suspicious processes and drivers
	'cmdscan',
	'consoles',
	'filescan',
	
	# TODO: Implement plugins requiring additional arguments
	# 'dlldump',
	# 'dumpfiles',
	# 'memdump',
	# 'moddump',
	# 'procdump',
	# 'processbl',
	# 'servicebl',

]

XP2003_PLUGINS = [
	# Step 3: Review network artifacts
	'connections',
	'connscan',
	'sockets',
	'sockscan',
]

VISTA_WIN2008_WIN7_PLUGINS = [
	# Step 3: Review network artifacts
	'netscan',
]

DEFAULT_OUTPUT_DIR = './'
DEFAULT_VOL_INVOCATION = 'vol.py'
MAX_SIMULTANEOUS_WORKERS = 6


class MemoryImage(object):
	"""
	Class representing a single memory image to analyze.

	Initializing a class will run Volatility imageinfo plugin to determine profile and KDBG offset,
	if they are not explicitly provided.
	"""
	def __init__(self, invocation, image_path, profile, kdbg, master_output_directory, plugins_list):
		self.invocation = invocation
		# Basename contains file extension (ex: DC011.raw)
		self.basename = os.path.basename(image_path)
		# Image_name removes the file extension (ex: DC011)
		self.image_name = '.'.join(self.basename.split('.')[:-1])
		self.abspath = os.path.abspath(image_path)
		self.output_directory = os.path.join(master_output_directory, self.image_name)
		self.profile = profile
		self.kdbg = kdbg
		self.valid_plugins = []

		# Create output directory if it doesn't exist
		if not os.path.exists(self.output_directory):
			os.makedirs(self.output_directory)  
		    
		# If the provided profile is invalid, exit program
		if self.profile:
			if not self.profile in SUPPORTED_PROFILES:
				logging.error('[{0}] Invalid profile {1} selected'.format(self.basename, args.profile))
				sys.exit()

		# If either the profile or the kdbg offset are not provided,
		# initiate imageinfo plugin.
		if not self.profile or not self.kdbg:
			logging.info('[{0}] Determining profile...'.format(self.basename))
			output_filename = f'{self.image_name}_imageinfo.txt'
			output_path = os.path.join(self.output_directory, output_filename)

			result_bytes = subprocess.check_output([self.invocation, '-f', self.abspath, 'imageinfo'])
			result_str = str(result_bytes)

			with open(output_path, 'wb') as output:
				output.write(result_bytes)

			profiles_regex = re.search('Suggested Profile\(s\) : ([^\n]*)',  result_str)
			auto_profiles = profiles_regex.group(1).split(', ')

			kdbg_regex = re.search(r'KDBG : (0x[a-fA-F0-9]*)', result_str)
			auto_kdbg = kdbg_regex.group(1)

		# If not already provided, select the first suggested profile
		if not self.profile:
			self.profile = auto_profiles[0]
		
		# If not already provided, select the first returned kdbg offset
		if not self.kdbg:
			self.kdbg = auto_kdbg

		# Populate plugin list for relevant OS type
		if plugins_list:
			with open(plugins_list, 'r') as ifile:
				for line in ifile:
					self.valid_plugins.append(line)
		else:
			OSType = re.match('(WinXP)|(Win2003)', self.profile)
			if OSType is not None:
				self.valid_plugins = BASE_PLUGINS + XP2003_PLUGINS
			else:
				self.valid_plugins = BASE_PLUGINS + VISTA_WIN2008_WIN7_PLUGINS
	
		logging.info('[{0}] Selected Profile: {1}'.format(self.basename, self.profile))
		logging.info('[{0}] Selected KDBG Offset: {1}'.format(self.basename, self.kdbg))

		for plugin in self.valid_plugins:
			logging.info('[{0}] Queuing plugin: {1}'.format(self.basename, plugin.strip('\n')))


class Task:
	def __init__(self, image_basename, plugin, output_path, commandline):
		self.image_basename = image_basename
		self.plugin = plugin
		self.output_path = output_path
		self.commandline = commandline


def generate_future_tasks(image):
	"""
	Generator function that produces a command to run every valid plugin against an image.

	Arguments:
		- image (MemoryImage)
	Yields:
		- Task containing command to run a plugin.
	"""
	for plugin in image.valid_plugins:
		if len(plugin.split(' ')) > 1:
			plugin_name = plugin.split(' ')[0].strip('\n')
			plugin_flags = [arg.strip('\n') for arg in plugin.split(' ')[1:]]
		else:
			plugin_name = plugin.strip('\n')
			plugin_flags = []

		output_filename = f'{image.image_name}_{plugin_name}.txt'
		output_path = os.path.join(image.output_directory, output_filename)

		commandline = [
			image.invocation,
			'-f', image.abspath,
			'--profile=' + image.profile,
			'--kdbg=' + image.kdbg,
			plugin_name
		]
		commandline += plugin_flags

		yield Task(image.basename, plugin_name, output_path, commandline) 


def execute_task(task):
	"""
	Execute a task to run a Volatility plugin on a separate process.
	"""
	logging.info('[{0}] Running Plugin: {1}'.format(task.image_basename, task.plugin))

	with open(task.output_path, 'w') as output:
		subprocess.call(task.commandline, stderr=subprocess.STDOUT, stdout=output)

	logging.info('[{0}] Plugin {1} output saved to {2}'.format(task.image_basename, 
		task.plugin, task.output_path))


def main():
	parser = argparse.ArgumentParser(description='Run all available Volatility plugins on a target image file.',
		epilog='''The first suggested profile will be automatically selected.
			All available plugins will be selected for the suggested profile.
			If the output directory does not exist, it will be created.
			The output files with follow a $plugin_$filename format.''')
	parser.add_argument('--invocation', help='Provide the desired invocation to execute Volatility. Defaults to "vol.py".')
	parser.add_argument('--readlist', help='Flag to read from a list of plugins rather than auto-detecting valid plugins.')
	parser.add_argument('--profile', help='Provide a valid profile and bypass auto-detection.')
	parser.add_argument('--kdbgoffset', help='Provide a valid kdbg offset and bypass auto-detection.')
	parser.add_argument('--output_dir', help='Path to output directory.')
	parser.add_argument('image_files', help='Path to memory image(s)', nargs='+')
	args = parser.parse_args()
	logging.info(f'Bulk Volatility Scanner running over {len(args.image_files)} image(s).')

	invocation = args.invocation if args.invocation else DEFAULT_VOL_INVOCATION
	output_dir = args.output_dir if args.output_dir else DEFAULT_OUTPUT_DIR

	master_output_directory = os.path.abspath(output_dir)
	if not os.path.exists(master_output_directory):
		os.makedirs(master_output_directory)
	logging.info(f'Output will be saved to: {master_output_directory}')

	profile = args.profile
	kdbg = args.kdbgoffset
	plugins_list = args.readlist
	tasks = []
	workers = []

	# Determine profiles and queue tasks for each memory image
	for image_path in args.image_files:
		image = MemoryImage(invocation, image_path, profile, kdbg, 
			master_output_directory, plugins_list)
		tasks.extend([task for task in generate_future_tasks(image)])

	# While pending tasks exist or workers are still processing:
	while (len(tasks) != 0) or (len(workers) != 0):
		logging.debug('Active Workers: {0}, Pending Tasks: {1}'.format(
			len(workers), len(tasks)))

		try:
			# If there are more pending tasks and we haven't reached our max worker count,
			# spin up a worker to start a new task.
			if len(tasks) > 0 and len(workers) < MAX_SIMULTANEOUS_WORKERS:
				task = tasks.pop()
				process = multiprocessing.Process(target=execute_task, args=(task,))
				workers.append({
					'plugin': task.plugin, 
					'image_basename': task.image_basename,
					'process': process})
				process.start()
			# Otherwise, poll workers intermittently and terminate finished workers 
			else:
				time.sleep(5)
				logging.debug('Polling workers....')
				for i, worker in enumerate(workers):
					logging.debug('[{0}] Worker for {1} is still alive?: {2}'.format(
						worker['image_basename'], worker['plugin'], worker['process'].is_alive()))
					if not worker['process'].is_alive():
						logging.debug('[{0}] Terminating finished worker for {1}'.format(
							worker['image_basename'], worker['plugin']))
						workers.pop(i)
		except KeyboardInterrupt:
			for worker in workers:
				worker['process'].terminate()
			break

	logging.info('Processing complete. Exiting gracefully.')
	sys.exit()


if __name__ == '__main__':
	main()
