# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import functools
import logging
import math
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from volatility3 import classproperty
from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)

INTEL_TRANSLATION_DEBUGGING = False


class Intel(linear.LinearlyMappedLayer):
    """Translation Layer for the Intel IA32 memory mapping."""

    _entry_format = "<I"
    _page_size_in_bits = 12
    _bits_per_register = 32
    # NOTE: _maxphyaddr is MAXPHYADDR as defined in the Intel specs *NOT* the maximum physical address
    _maxphyaddr = 32
    _maxvirtaddr = _maxphyaddr
    _structure = [('page directory', 10, False), ('page table', 10, True)]
    _direct_metadata = collections.ChainMap({'architecture': 'Intel32'}, {'mapped': True},
                                            interfaces.layers.TranslationLayerInterface._direct_metadata)

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)
        self._base_layer = self.config["memory_layer"]
        self._swap_layers: List[str] = []
        self._page_map_offset = self.config["page_map_offset"]

        # Assign constants
        self._initial_position = min(self._maxvirtaddr, self._bits_per_register) - 1
        self._initial_entry = self._mask(self._page_map_offset, self._initial_position, 0) | 0x1
        self._entry_size = struct.calcsize(self._entry_format)
        self._entry_number = self.page_size // self._entry_size

        # These can vary depending on the type of space
        self._index_shift = int(math.ceil(math.log2(struct.calcsize(self._entry_format))))
        self._structure_position_table: Dict[int, Tuple[str, int, bool]] = {}

    @classproperty
    @functools.lru_cache()
    def page_size(cls) -> int:
        """Page size for the intel memory layers.

        All Intel layers work on 4096 byte pages
        """
        return 1 << cls._page_size_in_bits

    @classproperty
    @functools.lru_cache()
    def bits_per_register(cls) -> int:
        """Returns the bits_per_register to determine the range of an
        IntelTranslationLayer."""
        return cls._bits_per_register

    @classproperty
    @functools.lru_cache()
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    @functools.lru_cache()
    def maximum_address(cls) -> int:
        return (1 << cls._maxvirtaddr) - 1

    @classproperty
    def structure(cls) -> List[Tuple[str, int, bool]]:
        return cls._structure

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (1 << (high_bit + 1)) - 1
        low_mask = (1 << low_bit) - 1
        mask = (high_mask ^ low_mask)
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        """Translates a specific offset based on paging tables.

        Returns the translated offset, the contiguous pagesize that the
        translated address lives in and the layer_name that the address
        lives in
        """
        # Setup the entry and how far we are through the offset
        # Position maintains the number of bits left to process
        # We or with 0x1 to ensure our page_map_offset is always valid
        position = self._initial_position
        entry = self._initial_entry

        if self.minimum_address > offset > self.maximum_address:
            raise exceptions.PagedInvalidAddressException(self.name, offset, position + 1, entry,
                                                          "Entry outside virtual address range: " + hex(entry))

        entry, position = self._translate_entry(offset, position, entry)

        # Now we're done
        if not (entry & 0x01):
            return self._handle_page_fault(self.name, offset, position + 1, entry, f"Page Fault at entry {hex(entry)} in page entry")

        page = self._mask(entry, self._maxphyaddr - 1, position + 1) | self._mask(offset, position, 0)

        return page, 1 << (position + 1), self._base_layer

    def _find_structure_index(self, position: int) -> Tuple[str, int, bool]:
        if not self._structure_position_table:
            counter = self._initial_position
            for name, size, large_page in self._structure:
                self._structure_position_table[counter] = name, size, large_page
                counter -= size
        return self._structure_position_table[position]

    def _handle_page_fault(self, name, offset, invalid_bits, entry, description):
        """Handles page faults"""
        raise exceptions.PagedInvalidAddressException(self.name, offset, invalid_bits, entry,
                                                      "Page Fault at entry " + hex(entry) + " in table " + name)

    def _translate_entry(self, offset: int, position: int, entry: int) -> Tuple[int, int]:
        """Translates a specific offset based on paging tables.

        Returns the translated entry value
        """
        name, size, large_page = self._find_structure_index(position)

        # Check we're present
        if not entry & 0x1:
            return self._handle_page_fault(self.name, offset, position + 1, entry,
                                           "Page Fault at entry " + hex(entry) + " in table " + name)
        # Check if we're a large page
        if large_page and (entry & (1 << 7)):
            # We're a large page, the rest is finished below
            # If we want to implement PSE-36, it would need to be done here
            return entry, position
        # Figure out how much of the offset we should be using
        start = position
        position -= size
        index = self._mask(offset, start, position + 1) >> (position + 1)

        # Grab the base address of the table we'll be getting the next entry from
        base_address = self._mask(entry, self._maxphyaddr - 1, size + self._index_shift)

        table = self._get_valid_table(base_address)
        if table is None:
            raise exceptions.PagedInvalidAddressException(self.name, offset, position + 1, entry,
                                                          "Page Fault at entry " + hex(entry) + " in table " + name)

        # Read the data for the next entry
        entry_data = table[(index << self._index_shift):(index << self._index_shift) + self._entry_size]

        if INTEL_TRANSLATION_DEBUGGING:
            vollog.log(
                constants.LOGLEVEL_VVVV, "Entry {} at index {} gives data {} as {}".format(
                    hex(entry), hex(index), hex(struct.unpack(self._entry_format, entry_data)[0]), name))

        # Read out the new entry from memory
        entry, = struct.unpack(self._entry_format, entry_data)

        if position < self._page_size_in_bits:
            return entry, position

        return self._translate_entry(offset, position, entry)

    @functools.lru_cache(1025)
    def _get_valid_table(self, base_address: int) -> Optional[bytes]:
        """Extracts the table, validates it and returns it if it's valid."""
        table = self._context.layers.read(self._base_layer, base_address, self.page_size)

        # If the table is entirely duplicates, then mark the whole table as bad
        if (table == table[:self._entry_size] * self._entry_number):
            return None
        return table

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all([
                self._context.layers[layer].is_valid(mapped_offset)
                for _, _, mapped_offset, _, layer in self.mapping(offset, length)
            ])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        stashed_offset = stashed_mapped_offset = stashed_size = stashed_mapped_size = stashed_map_layer = None
        for offset, size, mapped_offset, mapped_size, map_layer in self._mapping(offset, length, ignore_errors):
            if stashed_offset is None or (stashed_offset + stashed_size != offset) or (
                    stashed_mapped_offset + stashed_mapped_size != mapped_offset) or (stashed_map_layer != map_layer):
                # The block isn't contiguous
                if stashed_offset is not None:
                    yield stashed_offset, stashed_size, stashed_mapped_offset, stashed_mapped_size, stashed_map_layer
                # Update all the stashed values after output
                stashed_offset = offset
                stashed_mapped_offset = mapped_offset
                stashed_size = size
                stashed_mapped_size = mapped_size
                stashed_map_layer = map_layer
            else:
                # Part of an existing block
                stashed_size += size
                stashed_mapped_size += mapped_size
        # Yield whatever's left
        if (stashed_offset is not None and stashed_mapped_offset is not None and stashed_size is not None
                and stashed_mapped_size is not None and stashed_map_layer is not None):
            yield stashed_offset, stashed_size, stashed_mapped_offset, stashed_mapped_size, stashed_map_layer

    def _mapping(self,
                 offset: int,
                 length: int,
                 ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        if length == 0:
            try:
                mapped_offset, _, layer_name = self._translate(offset)
                if not self._context.layers[layer_name].is_valid(mapped_offset):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = mapped_offset)
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return
            yield offset, length, mapped_offset, length, layer_name
            return
        while length > 0:
            try:
                chunk_offset, page_size, layer_name = self._translate(offset)
                chunk_size = min(page_size - (chunk_offset % page_size), length)
                if not self._context.layers[layer_name].is_valid(chunk_offset, chunk_size):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = chunk_offset)
            except (exceptions.PagedInvalidAddressException, exceptions.InvalidAddressException) as excp:
                if not ignore_errors:
                    raise
                # We can jump more if we know where the page fault failed
                if isinstance(excp, exceptions.PagedInvalidAddressException):
                    mask = (1 << excp.invalid_bits) - 1
                else:
                    mask = (1 << self._page_size_in_bits) - 1
                length_diff = (mask + 1 - (offset & mask))
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layer names that this layer is dependent
        upon."""
        return [self._base_layer] + self._swap_layers

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'memory_layer', optional = False),
            requirements.LayerListRequirement(name = 'swap_layers', optional = True),
            requirements.IntRequirement(name = 'page_map_offset', optional = False),
            requirements.IntRequirement(name = 'kernel_virtual_offset', optional = True),
            requirements.StringRequirement(name = 'kernel_banner', optional = True)
        ]


class IntelPAE(Intel):
    """Class for handling Physical Address Extensions for Intel
    architectures."""

    _entry_format = "<Q"
    _bits_per_register = 32
    _maxphyaddr = 40
    _maxvirtaddr = 32
    _structure = [('page directory pointer', 2, False), ('page directory', 9, True), ('page table', 9, True)]
    _direct_metadata = collections.ChainMap({'pae': True}, Intel._direct_metadata)


class Intel32e(Intel):
    """Class for handling 64-bit (32-bit extensions) for Intel
    architectures."""

    _direct_metadata = collections.ChainMap({'architecture': 'Intel64'}, Intel._direct_metadata)
    _entry_format = "<Q"
    _bits_per_register = 64
    _maxphyaddr = 52
    _maxvirtaddr = 48
    _structure = [('page map layer 4', 9, False), ('page directory pointer', 9, True), ('page directory', 9, True),
                  ('page table', 9, True)]


class WindowsMixin(Intel):
    _swap_bit_offset = 32

    def _get_kernel_module(self):
        kvo = self.config.get('kernel_virtual_offset', None)
        if kvo is None:
            return None

        for module_name in self.context.modules:
            if self.context.modules[module_name].offset == kvo:
                return self.context.modules[module_name]

        return None

    @functools.lru_cache()
    def _get_invalid_pte_mask(self, kernel):
        if kernel.has_symbol("MiInvalidPteMask"):
            pte_size = kernel.get_type("_MMPTE_HARDWARE").vol.size
            pte_type = "unsigned int"
            if pte_size == 8:
                pte_type = "unsigned long long"

            return kernel.object(pte_type, offset=kernel.get_symbol("MiInvalidPteMask").address)

        if kernel.has_symbol("MiState"):
            system_information = kernel.object("_MI_SYSTEM_INFORMATION", offset=kernel.get_symbol("MiState").address)
            return system_information.Hardware.InvalidPteMask

        return 0

    @functools.lru_cache()
    def _get_PageFileLow_shift(self, kernel):
        mmpte_software_type = kernel.get_type("_MMPTE_SOFTWARE")
        if mmpte_software_type.vol.members.get("SwizzleBit", None) is None:
            return 1 # The old shift

        return 12 # The new shift

    def _handle_page_fault(self, layer_name, offset, invalid_bits, entry, description):
        kernel = self._get_kernel_module()
        if kernel is None:
            raise exceptions.PagedInvalidAddressException(self.name, offset, invalid_bits, entry, "kernel module not found!")

        tbit = bool(entry & (1 << 11))
        pbit = bool(entry & (1 << 10))
        vbit = bool(entry & 1)
        entry &= ~self._get_invalid_pte_mask(kernel)
        
        # Handle transition page
        if tbit and not pbit:
            position = invalid_bits - 1
            name, size, _ = self._find_structure_index(position)
            index = self._mask(offset, position, position + size) >> (position + size)

            # Grab the base address of the table we'll be getting the next entry from
            base_address = self._mask(entry, self._maxphyaddr - 1, size + self._index_shift)

            table = self._get_valid_table(base_address)
            if table is None:
                raise exceptions.PagedInvalidAddressException(self.name, offset, position + 1, entry,
                                                              "Page Fault at entry " + hex(
                                                                  entry) + " in table " + name)

            # Read the data for the next entry
            entry_data = table[(index << self._index_shift):(index << self._index_shift) + self._entry_size]
            return super()._translate_entry(offset, invalid_bits, entry)

        # Handle Swap failure
        if (not tbit and not pbit and not vbit) and ((entry >> self._swap_bit_offset) != 0):
            pagefile_idx = (entry >> self._get_PageFileLow_shift(kernel)) & 0xF
            swap_offset = entry >> self._swap_bit_offset << invalid_bits

            if self.config.get('swap_layers', False):
                swap_layer_name = self.config.get(
                    interfaces.configuration.path_join('swap_layers', 'swap_layers' + str(pagefile_idx)), None)
                if swap_layer_name:
                    return swap_offset, 1 << invalid_bits, swap_layer_name
            raise exceptions.SwappedInvalidAddressException(layer_name = layer_name,
                                                            invalid_address = offset,
                                                            invalid_bits = invalid_bits,
                                                            entry = entry,
                                                            swap_offset = swap_offset)

        raise super()._handle_page_fault(layer_name, offset, invalid_bits, entry, description)


### These must be full separate classes so that JSON configs re-create them properly


class WindowsIntel(WindowsMixin, Intel):
    pass


class WindowsIntelPAE(WindowsMixin, IntelPAE):
    pass


class WindowsIntel32e(WindowsMixin, Intel32e):
    # TODO: Fix appropriately in a future release.
    # Currently just a temprorary workaround to deal with custom bit flag
    # in the PFN field for pages in transition state.
    # See https://github.com/volatilityfoundation/volatility3/pull/475
    _maxphyaddr = 45
