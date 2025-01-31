# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional, Union

from volatility3.framework import interfaces, objects, constants


def rol(value: int, count: int, max_bits: int = 64) -> int:
    """A rotate-left instruction in Python"""
    max_bits_mask = (1 << max_bits) - 1
    return (value << count % max_bits) & max_bits_mask | (
        (value & max_bits_mask) >> (max_bits - (count % max_bits))
    )


def bswap_32(value: int) -> int:
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)

    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF


def bswap_64(value: int) -> int:
    low = bswap_32(value >> 32)
    high = bswap_32(value & 0xFFFFFFFF)

    return ((high << 32) | low) & 0xFFFFFFFFFFFFFFFF


def array_to_string(
    array: "objects.Array",
    count: Optional[int] = None,
    errors: str = "replace",
    block_size=32,
) -> str:
    """Takes a Volatility 'Array' of characters and returns a Python string.

    Args:
        array: The Volatility `Array` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the character array.
    """
    # TODO: Consider checking the Array's target is a native char
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")

    if count is None:
        count = array.vol.count

    return address_to_string(
        context=array._context,
        layer_name=array.vol.layer_name,
        address=array.vol.offset,
        count=count,
        errors=errors,
        block_size=block_size,
    )


def pointer_to_string(
    pointer: "objects.Pointer",
    count: int,
    errors: str = "replace",
    block_size=32,
) -> str:
    """Takes a Volatility 'Pointer' to characters and returns a Python string.

    Args:
        pointer: A `Pointer` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the data referenced by the pointer.
    """
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")

    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")

    return address_to_string(
        context=pointer._context,
        layer_name=pointer.vol.layer_name,
        address=pointer,
        count=count,
        errors=errors,
        block_size=block_size,
    )


def address_to_string(
    context: interfaces.context.ContextInterface,
    layer_name: str,
    address: int,
    count: int,
    errors: str = "replace",
    block_size=32,
) -> str:
    """Reads a null-terminated string from a given specified memory address, processing
       it in blocks for efficiency.

    Args:
        context: The context used to retrieve memory layers and symbol tables
        layer_name: The name of the memory layer to read from
        address: The address where the string is located in memory
        count: The number of bytes to read
        errors: The error handling scheme to use for encoding errors. Defaults to "replace"
        block_size: Reading block size. Defaults to 32

    Returns:
        The decoded string extracted from memory.
    """
    if not isinstance(address, int):
        raise TypeError("It takes an int")

    if count < 1:
        raise ValueError("It requires a positive count")

    layer = context.layers[layer_name]
    text = b""
    while len(text) < count:
        current_block_size = min(count - len(text), block_size)
        temp_text = layer.read(address + len(text), current_block_size)
        idx = temp_text.find(b"\x00")
        if idx != -1:
            temp_text = temp_text[:idx]
            text += temp_text
            break
        text += temp_text

    return text.decode(errors=errors)


def array_of_pointers(
    array: interfaces.objects.ObjectInterface,
    count: int,
    subtype: Union[str, interfaces.objects.Template],
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.ObjectInterface:
    """Takes an object, and recasts it as an array of pointers to subtype."""
    symbol_table = array.vol.type_name.split(constants.BANG)[0]
    if isinstance(subtype, str) and context is not None:
        subtype = context.symbol_space.get_type(subtype)
    if not isinstance(subtype, interfaces.objects.Template) or subtype is None:
        raise TypeError(
            "Subtype must be a valid template (or string name of an object template)"
        )
    # We have to clone the pointer class, or we'll be defining the pointer subtype for all future pointers
    subtype_pointer = context.symbol_space.get_type(
        symbol_table + constants.BANG + "pointer"
    ).clone()
    subtype_pointer.update_vol(subtype=subtype)
    return array.cast("array", count=count, subtype=subtype_pointer)
