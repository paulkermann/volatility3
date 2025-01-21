# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# Public researches: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fixing-A-Memory-Forensics-Blind-Spot-Linux-Kernel-Tracing-wp.pdf

import logging
from typing import List, Iterable, Tuple, Set
from enum import auto, IntFlag
from volatility3.plugins.linux import hidden_modules, modxview
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid, NotAvailableValue
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.symbols.linux.utilities import modules as modules_utilities
from volatility3.framework.constants import architectures

vollog = logging.getLogger(__name__)


# https://docs.python.org/3.13/library/enum.html#enum.IntFlag
class FTRACE_OPS_FLAGS(IntFlag):
    """Denote the state of an ftrace_ops struct.
    Based on https://elixir.bootlin.com/linux/v6.13-rc3/source/include/linux/ftrace.h#L255.
    """

    FTRACE_OPS_FL_ENABLED = auto()
    FTRACE_OPS_FL_DYNAMIC = auto()
    FTRACE_OPS_FL_SAVE_REGS = auto()
    FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED = auto()
    FTRACE_OPS_FL_RECURSION = auto()
    FTRACE_OPS_FL_STUB = auto()
    FTRACE_OPS_FL_INITIALIZED = auto()
    FTRACE_OPS_FL_DELETED = auto()
    FTRACE_OPS_FL_ADDING = auto()
    FTRACE_OPS_FL_REMOVING = auto()
    FTRACE_OPS_FL_MODIFYING = auto()
    FTRACE_OPS_FL_ALLOC_TRAMP = auto()
    FTRACE_OPS_FL_IPMODIFY = auto()
    FTRACE_OPS_FL_PID = auto()
    FTRACE_OPS_FL_RCU = auto()
    FTRACE_OPS_FL_TRACE_ARRAY = auto()
    FTRACE_OPS_FL_PERMANENT = auto()
    FTRACE_OPS_FL_DIRECT = auto()
    FTRACE_OPS_FL_SUBOP = auto()


class Check_ftrace(interfaces.plugins.PluginInterface):
    """Detect ftrace hooking"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 17, 0)
    additional_description = """Investigate the ftrace infrastructure to uncover kernel attached callbacks, which can be leveraged
    to hook kernel functions and modify their behaviour."""
    _hidden_modules_run = False
    """Flag to determine if the hidden_modules plugin was run, 
    in the context of this plugin."""

    @staticmethod
    def get_requirements() -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="modules_utilities",
                component=modules_utilities.Modules,
                version=(1, 0, 0),
            ),
            requirements.PluginRequirement(
                name="modxview", plugin=modxview.Modxview, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="hidden_modules",
                plugin=hidden_modules.Hidden_modules,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="show_ftrace_flags",
                description="Show ftrace flags associated with an ftrace_ops struct",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def _set_hidden_modules_run(cls) -> None:
        """Use a self-contained setter, to prevent running hidden_modules multiple times."""
        cls._hidden_modules_run = True

    @staticmethod
    def extract_hash_table_filters(
        ftrace_ops: interfaces.objects.ObjectInterface,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Wrap the process of walking to every ftrace_func_entry of an ftrace_ops.
        Those are stored in a hash table of filters that indicates the addresses hooked.

        Args:
            ftrace_ops: The ftrace_ops struct to walk through

        Returns:
            An iterable of ftrace_func_entry structs
        """

        try:
            current_bucket_ptr = ftrace_ops.func_hash.filter_hash.buckets.first
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VV,
                f"ftrace_func_entry list of ftrace_ops@{ftrace_ops.vol.offset:#x} is empty/invalid. Skipping it...",
            )
            return []

        while current_bucket_ptr.is_readable():
            yield current_bucket_ptr.dereference().cast("ftrace_func_entry")
            current_bucket_ptr = current_bucket_ptr.next

    @classmethod
    def parse_ftrace_ops(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        known_modules: Set[extensions.module],
        ftrace_ops: interfaces.objects.ObjectInterface,
        parse_flags: bool = False,
    ) -> Tuple:
        """Parse an ftrace_ops struct to highlight ftrace kernel hooking.
        Iterates over embedded ftrace_func_entry entries, which point to hooked memory areas.

        Args:
            known_modules: A set of known modules to iterate over, used to locate callbacks origin
            ftrace_ops: The ftrace_ops struct to parse
            parse_flags: Whether to parse ftrace_ops flags or not

        Yields:
            A tuple containing a selection of useful fields (callback, hook, module) related to an ftrace_func_entry struct
        """
        kernel = context.modules[kernel_name]
        callback = ftrace_ops.func

        # Try to lookup within the known modules if the callback address fits
        module = modules_utilities.Modules.module_lookup_by_address(
            context, kernel.layer_name, known_modules, callback
        )
        # Run hidden_modules plugin if a callback origin couldn't be determined (only done once, results are re-used afterwards)
        if module is None and not cls._hidden_modules_run:
            vollog.info(
                f"A callback module origin could not be determined. hidden_modules plugin will be run to detect additional modules.",
            )
            known_modules_addresses = set(
                context.layers[kernel.layer_name].canonicalize(module.vol.offset)
                for module in known_modules
            )
            modules_memory_boundaries = (
                hidden_modules.Hidden_modules.get_modules_memory_boundaries(
                    context, kernel_name
                )
            )
            known_modules.update(
                hidden_modules.Hidden_modules.get_hidden_modules(
                    context,
                    kernel_name,
                    known_modules_addresses,
                    modules_memory_boundaries,
                )
            )
            cls._set_hidden_modules_run()
            # Lookup the updated list to see if hidden_modules was able
            # to find the missing module
            module = modules_utilities.Modules.module_lookup_by_address(
                context, kernel.layer_name, known_modules, callback
            )

        # Fetch more information about the module
        if module:
            module_address = format_hints.Hex(module.vol.offset)
            module_name = module.get_name() or NotAvailableValue()
            callback_symbol = (
                module.get_symbol_by_address(callback) or NotAvailableValue()
            )
        else:
            vollog.warning(
                f"Could not determine ftrace_ops@{ftrace_ops.vol.offset:#x} callback {callback:#x} module origin.",
            )
            module_address = NotAvailableValue()
            module_name = NotAvailableValue()
            callback_symbol = NotAvailableValue()

        # Iterate over ftrace_func_entry list
        for ftrace_func_entry in cls.extract_hash_table_filters(ftrace_ops):
            hook_address = ftrace_func_entry.ip.cast("pointer")

            # Determine the symbols associated with a hook
            hooked_symbols = kernel.get_symbols_by_absolute_location(hook_address)
            hooked_symbols = ",".join(
                [s.split(constants.BANG)[-1] for s in hooked_symbols]
            )
            parsed_entry = (
                format_hints.Hex(ftrace_ops.vol.offset),
                callback_symbol,
                format_hints.Hex(callback),
                hooked_symbols or NotAvailableValue(),
                module_name,
                module_address,
            )

            if parse_flags:
                # e.g. FTRACE_OPS_FL_ENABLED,FTRACE_OPS_FL_DYNAMIC
                parsed_entry += (
                    FTRACE_OPS_FLAGS(ftrace_ops.flags).name.replace("|", ","),
                )

            return parsed_entry

    @staticmethod
    def iterate_ftrace_ops_list(
        context: interfaces.context.ContextInterface, kernel_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Iterate over (ftrace_ops *)ftrace_ops_list.

        Returns:
            An iterable of ftrace_ops structs
        """
        kernel = context.modules[kernel_name]
        current_frace_ops_ptr = kernel.object_from_symbol("ftrace_ops_list")
        ftrace_list_end = kernel.object_from_symbol("ftrace_list_end")

        while current_frace_ops_ptr.is_readable():
            # ftrace_list_end is not considered a valid struct
            # see kernel function test_rec_ops_needs_regs
            if current_frace_ops_ptr != ftrace_list_end.vol.offset:
                yield current_frace_ops_ptr.dereference()
                current_frace_ops_ptr = current_frace_ops_ptr.next
            else:
                break

    def _generator(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]

        if not kernel.has_symbol("ftrace_ops_list"):
            raise exceptions.SymbolError(
                "ftrace_ops_list",
                kernel.symbol_table_name,
                'The provided symbol table does not include the "ftrace_ops_list" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupted.',
            )

        # Do not run hidden_modules by default, but only on failure to find a module
        known_modules = set(
            modxview.Modxview.flatten_run_modules_results(
                modxview.Modxview.run_modules_scanners(
                    self.context, kernel_name, run_hidden_modules=False
                )
            )
        )
        for ftrace_ops in self.iterate_ftrace_ops_list(self.context, kernel_name):
            ftrace_ops_parsed = self.parse_ftrace_ops(
                self.context,
                kernel_name,
                known_modules,
                ftrace_ops,
                self.config.get("show_ftrace_flags"),
            )
            if ftrace_ops_parsed is not None:
                yield (0, (ftrace_ops_parsed))

    def run(self):
        columns = [
            ("ftrace_ops address", format_hints.Hex),
            ("Callback", str),
            ("Callback address", format_hints.Hex),
            ("Hooked symbols", str),
            ("Module", str),
            ("Module address", format_hints.Hex),
        ]

        if self.config.get("show_ftrace_flags"):
            columns.append(("Flags", str))

        return TreeGrid(
            columns,
            self._generator(),
        )
