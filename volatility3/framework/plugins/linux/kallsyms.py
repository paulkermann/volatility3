# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Union

from volatility3.framework import interfaces, renderers
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.constants import architectures
from volatility3.framework.symbols.linux import kallsyms


vollog = logging.getLogger(__name__)


class Kallsyms(plugins.PluginInterface):
    """Kallsyms symbols enumeration plugin.

    If no arguments are provided, all symbols are included: core, modules, ftrace, and BPF.
    Alternatively, you can use any combination of --only-core, --only-modules, --only-ftrace,
    and --only-bpf to customize the output.
    """

    _required_framework_version = (2, 19, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="Kallsyms", component=kallsyms.Kallsyms, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="only_core",
                description="Include core symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only_modules",
                description="Include module symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only_ftrace",
                description="Include ftrace symbols",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only_bpf",
                description="Include bpf symbols",
                default=False,
                optional=True,
            ),
        ]

    def _get_symbol_size(
        self, kassymbol: kallsyms.KASSymbol
    ) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        # Symbol sizes are calculated using the address of the next non-aliased
        # symbol or the end of the kernel text area _end/_etext. However, some kernel
        # symbols live beyond that area. For these symbols, the size will be negative,
        # resulting in incorrect values. Unfortunately, there isn't much that can be done
        # in such cases.
        # See comments on .init.scratch in arch/x86/kernel/vmlinux.lds.S for details
        return kassymbol.size if kassymbol.size >= 0 else renderers.NotAvailableValue()

    def _generator(self):
        module_name = self.config["kernel"]
        vmlinux = self.context.modules[module_name]

        kas = kallsyms.Kallsyms(
            context=self.context,
            layer_name=vmlinux.layer_name,
            module_name=self.config["kernel"],
        )

        only_core = self.config.get("only_core", False)
        only_modules = self.config.get("only_modules", False)
        only_ftrace = self.config.get("only_ftrace", False)
        only_bpf = self.config.get("only_bpf", False)

        symbols_flags = (only_core, only_modules, only_ftrace, only_bpf)
        if not any(symbols_flags):
            only_core = only_modules = only_ftrace = only_bpf = True

        symbol_geneators = []
        if only_core:
            symbol_geneators.append(kas.get_core_symbols())
        if only_modules:
            symbol_geneators.append(kas.get_modules_symbols())
        if only_ftrace:
            symbol_geneators.append(kas.get_ftrace_symbols())
        if only_bpf:
            symbol_geneators.append(kas.get_bpf_symbols())

        for symbols_generator in symbol_geneators:
            for kassymbol in symbols_generator:
                # Symbol sizes are calculated using the address of the next non-aliased
                # symbol or the end of the kernel text area _end/_etext. However, some kernel
                # symbols are located beyond that area, which causes this method to fail for
                # the last symbol, resulting in a negative size.
                # See comments on .init.scratch in arch/x86/kernel/vmlinux.lds.S for details
                symbol_size = self._get_symbol_size(kassymbol)
                fields = (
                    format_hints.Hex(kassymbol.address),
                    kassymbol.type,
                    symbol_size,
                    kassymbol.exported,
                    kassymbol.subsystem,
                    kassymbol.module_name,
                    kassymbol.name,
                    kassymbol.type_description or renderers.NotAvailableValue(),
                )
                yield 0, fields

    def run(self):
        headers = [
            ("Addr", format_hints.Hex),
            ("Type", str),
            ("Size", int),
            ("Exported", bool),
            ("SubSystem", str),
            ("ModuleName", str),
            ("SymbolName", str),
            ("Description", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
