import sys

required_python_version = (3, 8, 0)
if (
    sys.version_info.major != required_python_version[0]
    or sys.version_info.minor < required_python_version[1]
    or (
        sys.version_info.minor == required_python_version[1]
        and sys.version_info.micro < required_python_version[2]
    )
):
    raise RuntimeError(
        f"Volatility framework requires python version {required_python_version[0]}.{required_python_version[1]}.{required_python_version[2]} or greater"
    )
