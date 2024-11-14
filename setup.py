from setuptools import setup
from Cython.Build import cythonize
from cx_Freeze import Executable

setup(
    name="AntivirusApp",
    ext_modules=cythonize("antiviruspro.py"),  # Cythonize the Python file
    options={
        "build_exe": {
            "packages": ["PySide6", "yara"],  # Include necessary packages
            "optimize": 2,  # Optimizations
            "build_exe": "build_exe_output",  # Separate output directory for the executable
        }
    },
    executables=[
        Executable(
            "antiviruspro.py",  # Your Python script
            base="Win32GUI",     # This prevents the console window
            icon="assets/hacimuradantivirusbabaproedition.ico",  # Optional: your custom app icon
            target_name="hacimuradantivirusbabaproedition.exe",  # Optional: set the output executable name
            uac_admin="1",  # Add the manifest to request admin privileges
        )
    ]
)
