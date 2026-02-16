from types import SimpleNamespace
import importlib
import copy
import socket
import os
import argparse

from nettacker.core.utils.huey_config import huey
from nettacker import logger
from nettacker.core.messages import messages as _
from nettacker.core.socks_proxy import set_socks_proxy

log = logger.get_logger()


@huey.task(retries=3, retry_delay=2)
def run_engine_task(library, sub_step, module_name, target, scan_id, module_inputs, process_number, module_thread_number, total_module_thread_number, request_number_counter, total_number_of_requests):
	try:
		engine = getattr(
		importlib.import_module(f"nettacker.core.lib.{library.lower()}"),
			f"{library.capitalize()}Engine"
				)()

		engine.run(
			sub_step,
			module_name,
			target,
			scan_id,
			module_inputs,
			process_number,
			module_thread_number,
			total_module_thread_number,
			request_number_counter,
			total_number_of_requests,
		)
	except Exception as e:
		log.warn(_("task_warning").format(library.capitalize()))
		print(e)			# For debugging

@huey.task(retries=3, retry_delay=2)
def new_scan_task(form_values):
	from nettacker.core.app import Nettacker
	form_values["targets"] = [form_values["targets"]]
	nettacker_app = Nettacker(api_arguments = SimpleNamespace(**form_values))
	app_arguments = SimpleNamespace(**form_values)

	print("These are the arguments to nettacker: {}".format(app_arguments))			# Is it splitting en.wikipedia.org
	# Bruh till here everything's fine!
	if not isinstance(app_arguments.selected_modules, list):
		app_arguments.selected_modules = [app_arguments.selected_modules]			# make sure we don't come here if we have actually selected more.
	nettacker_app.arguments = app_arguments
	nettacker_app.run()

	return vars(app_arguments)


from nettacker.core.module import Module


@huey.task(retries=3, retry_delay=2)
def scan_target_task(target, arguments, module_name, scan_id, process_number, thread_number, total_number_threads):
	options = argparse.Namespace(**copy.deepcopy(arguments))
	socket.socket, socket.getaddrinfo = set_socks_proxy(options.socks_proxy)
	module = Module(
		module_name,
		options,
		target,
		scan_id,
		process_number,
		thread_number,
		total_number_threads,
	)

	module.load()
	module.generate_loops()
	module.sort_loops()
	module.start()

	log.verbose_event_info(
		_("finished_parallel_module_scan").format(
			process_number, module_name, target, thread_number, total_number_threads
		)
	)
	return os.EX_OK
