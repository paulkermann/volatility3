import warnings
from typing import Iterable, Iterator, List, Optional, Tuple

from volatility3 import framework
from volatility3.framework import constants, interfaces
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import extensions


class Modules(interfaces.configuration.VersionableInterface):
    """Kernel modules related utilities."""

    _version = (1, 1, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def module_lookup_by_address(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        modules: Iterable[extensions.module],
        target_address: int,
    ) -> Optional[extensions.module]:
        """
        Determine if a target address lies in a module memory space.
        Returns the module where the provided address lies.

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            modules: An iterable containing the modules to match the address against
            target_address: The address to check for a match

        Returns:
            The first memory module in which the address fits

        Kernel documentation:
            "within_module" and "within_module_mem_type" functions
        """
        matches = []
        seen_addresses = set()
        for module in modules:
            _, start, end = cls.mask_mods_list(context, layer_name, [module])[0]
            if (
                start <= target_address < end
                and module.vol.offset not in seen_addresses
            ):
                matches.append(module)
                seen_addresses.add(module.vol.offset)

        if len(matches) > 1:
            warnings.warn(
                f"Address {hex(target_address)} fits in modules at {[hex(module.vol.offset) for module in matches]}, indicating potential modules memory space overlap.",
                UserWarning,
            )
            return matches[0]
        elif len(matches) == 1:
            return matches[0]

        return None

    @classmethod
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        mods: Iterator[interfaces.objects.ObjectInterface],
    ) -> List[Tuple[str, int, int]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[layer_name].address_mask

        return [
            (
                utility.array_to_string(mod.name),
                mod.get_module_base() & mask,
                (mod.get_module_base() & mask) + mod.get_core_size(),
            )
            for mod in mods
        ]

    @classmethod
    def lookup_module_address(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        handlers: List[Tuple[str, int, int]],
        target_address: int,
    ) -> Tuple[str, str]:
        """
        Searches between the start and end address of the kernel module using target_address.
        Returns the module and symbol name of the address provided.
        """
        kernel_module = context.modules[kernel_module_name]
        mod_name = "UNKNOWN"
        symbol_name = "N/A"

        for name, start, end in handlers:
            if start <= target_address <= end:
                mod_name = name
                if name == constants.linux.KERNEL_NAME:
                    symbols = list(
                        kernel_module.get_symbols_by_absolute_location(target_address)
                    )

                    if len(symbols):
                        symbol_name = (
                            symbols[0].split(constants.BANG)[1]
                            if constants.BANG in symbols[0]
                            else symbols[0]
                        )

                break

        return mod_name, symbol_name
