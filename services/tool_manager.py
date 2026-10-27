import shutil
import importlib
import logging
from typing import Dict, Any, List, Optional
from utils.process_utils import run_external_command

logger = logging.getLogger("FileGuard.ToolManager")

class ToolManager:
    """
    Detects and manages the availability and versions of external binaries and Python recovery libraries.
    Ensures unavailable external tools are never recommended or executed.
    """

    _cached_tools: dict[str, dict] | None = None

    @classmethod
    def get_system_tools(cls, force_refresh: bool = False) -> dict[str, dict]:
        """
        Inspects all external command-line utilities and Python modules.
        Returns a dictionary keyed by tool name with availability and metadata.
        """
        if cls._cached_tools is not None and not force_refresh:
            return cls._cached_tools

        tools = {}

        # 1. QPDF CLI
        qpdf_bin = shutil.which("qpdf")
        if not qpdf_bin:
            # Check common Windows paths
            for candidate in [
                r"C:\Program Files\qpdf\bin\qpdf.exe",
                r"C:\Program Files (x86)\qpdf\bin\qpdf.exe",
                r"C:\qpdf\bin\qpdf.exe",
                r"C:\tools\qpdf\bin\qpdf.exe",
                r"D:\qpdf\bin\qpdf.exe",
                r"E:\qpdf\bin\qpdf.exe"
            ]:
                if candidate and shutil.which(candidate):
                    qpdf_bin = candidate
                    break
        
        qpdf_ver = "Unknown"
        qpdf_avail = bool(qpdf_bin)
        if qpdf_avail:
            ok, out, _ = run_external_command([qpdf_bin, "--version"], timeout=5)
            if ok and out:
                qpdf_ver = out.splitlines()[0].strip()

        tools["qpdf"] = {
            "name": "QPDF CLI",
            "type": "binary",
            "available": qpdf_avail,
            "path": qpdf_bin,
            "version": qpdf_ver,
            "description": "High-performance PDF structural linearizer and cross-reference table repair tool.",
            "install_guide": "Install via 'winget install qpdf.qpdf' or 'choco install qpdf'."
        }

        # 2. LibreOffice (Optional Headless Conversion)
        lo_bin = shutil.which("soffice") or shutil.which("libreoffice")
        if not lo_bin:
            for candidate in [
                r"C:\Program Files\LibreOffice\program\soffice.exe",
                r"C:\Program Files (x86)\LibreOffice\program\soffice.exe"
            ]:
                if shutil.which(candidate):
                    lo_bin = candidate
                    break
        
        tools["libreoffice"] = {
            "name": "LibreOffice Headless",
            "type": "binary",
            "available": bool(lo_bin),
            "path": lo_bin,
            "version": "Available" if lo_bin else "Missing",
            "description": "Headless office suite conversion and document verification.",
            "install_guide": "Install LibreOffice to enable native headless conversion for office documents."
        }

        # 3. 7-Zip CLI (Optional ZIP salvaging)
        sz_bin = shutil.which("7z") or shutil.which("7za")
        if not sz_bin:
            for candidate in [
                r"C:\Program Files\7-Zip\7z.exe",
                r"C:\Program Files (x86)\7-Zip\7z.exe"
            ]:
                if shutil.which(candidate):
                    sz_bin = candidate
                    break

        tools["7zip"] = {
            "name": "7-Zip CLI",
            "type": "binary",
            "available": bool(sz_bin),
            "path": sz_bin,
            "version": "Available" if sz_bin else "Missing",
            "description": "Deep corrupted archive and OpenXML container decompression.",
            "install_guide": "Install via 'winget install 7zip.7zip'."
        }

        # 4. MuPDF mutool CLI
        mutool_bin = shutil.which("mutool")
        if not mutool_bin:
            for candidate in [
                r"C:\Program Files\mupdf\mutool.exe",
                r"C:\Program Files (x86)\mupdf\mutool.exe",
                r"C:\tools\mupdf\mutool.exe",
                r"C:\mupdf\mutool.exe"
            ]:
                if candidate and shutil.which(candidate):
                    mutool_bin = candidate
                    break
        
        mutool_ver = "Unknown"
        mutool_avail = bool(mutool_bin)
        if mutool_avail:
            ok, out, _ = run_external_command([mutool_bin, "-v"], timeout=5)
            if ok and out:
                mutool_ver = out.splitlines()[0].strip()

        tools["mutool"] = {
            "name": "MuPDF mutool CLI",
            "type": "binary",
            "available": mutool_avail,
            "path": mutool_bin,
            "version": mutool_ver if mutool_avail else "Missing",
            "description": "MuPDF command-line repair, stream cleaner, and object extractor.",
            "install_guide": "Install via 'choco install mupdf' or download from mupdf.com/downloads."
        }

        # 5. jpeginfo CLI
        jpeginfo_bin = shutil.which("jpeginfo")
        tools["jpeginfo"] = {
            "name": "jpeginfo CLI",
            "type": "binary",
            "available": bool(jpeginfo_bin),
            "path": jpeginfo_bin,
            "version": "Available" if jpeginfo_bin else "Missing",
            "description": "Command-line JPEG header, marker, and stream integrity checker.",
            "install_guide": "Install via 'winget install jpeginfo' or package manager."
        }

        # 6. jpegtran CLI
        jpegtran_bin = shutil.which("jpegtran")
        tools["jpegtran"] = {
            "name": "jpegtran CLI",
            "type": "binary",
            "available": bool(jpegtran_bin),
            "path": jpegtran_bin,
            "version": "Available" if jpegtran_bin else "Missing",
            "description": "Lossless JPEG transformation, marker reconstruction, and scan repair utility.",
            "install_guide": "Install via libjpeg-turbo package or 'choco install libjpeg-turbo'."
        }

        # 7. pngcheck CLI
        pngcheck_bin = shutil.which("pngcheck")
        tools["pngcheck"] = {
            "name": "pngcheck CLI",
            "type": "binary",
            "available": bool(pngcheck_bin),
            "path": pngcheck_bin,
            "version": "Available" if pngcheck_bin else "Missing",
            "description": "PNG chunk, CRC checksum, and compression integrity verification utility.",
            "install_guide": "Install via 'choco install pngcheck' or download from libpng.org."
        }

        # 8. Python Recovery Libraries
        py_libs = [
            ("pikepdf", "pikepdf", "C++ QPDF Python binding for fast PDF object repair."),
            ("pymupdf", "fitz", "PyMuPDF high-speed heuristic stream repair and page renderer."),
            ("pypdf", "pypdf", "Permissive pure-Python PDF reader and object stream rebuilder."),
            ("pdfplumber", "pdfplumber", "PDF text, table, and layout extraction engine."),
            ("python-docx", "docx", "OpenXML Word document parser and paragraph rebuilder."),
            ("openpyxl", "openpyxl", "OpenXML Excel spreadsheet parser and cell recovery engine."),
            ("python-pptx", "pptx", "OpenXML PowerPoint presentation and slide builder."),
            ("pillow", "PIL", "Python Imaging Library for image decoding, marker repair, and raster validation."),
            ("reportlab", "reportlab", "PDF document synthesis and token stream re-emitter.")
        ]

        for display_name, mod_name, desc in py_libs:
            avail = False
            ver = "Unknown"
            try:
                mod = importlib.import_module(mod_name)
                avail = True
                ver = getattr(mod, "__version__", "Installed")
            except ImportError:
                avail = False
                ver = "Not Installed"

            tools[display_name] = {
                "name": display_name,
                "type": "python_library",
                "available": avail,
                "version": ver,
                "description": desc,
                "install_guide": f"Run 'pip install {display_name}'."
            }

        cls._cached_tools = tools
        return tools

    @classmethod
    def get_available_tool_names(cls) -> list[str]:
        """Returns a list of all currently available tool/library identifiers."""
        tools = cls.get_system_tools()
        return [k for k, v in tools.items() if v.get("available")]

    @classmethod
    def is_tool_available(cls, tool_name: str) -> bool:
        """Checks if a specific tool is available."""
        tools = cls.get_system_tools()
        t = tools.get(tool_name.lower())
        return bool(t and t.get("available"))

    @classmethod
    def check_tool_availability(cls, tool_name: str) -> bool:
        """Alias for is_tool_available satisfying standard interface."""
        return cls.is_tool_available(tool_name)

    @classmethod
    def get_dependency_report(cls) -> dict[str, Any]:
        """
        Generates structured report of all core Python libraries and external binaries.
        Identifies missing dependencies with clear install guidance.
        """
        all_tools = cls.get_system_tools(force_refresh=True)
        installed = {k: v for k, v in all_tools.items() if v["available"]}
        missing = {k: v for k, v in all_tools.items() if not v["available"]}
        return {
            "all_tools": all_tools,
            "installed_count": len(installed),
            "missing_count": len(missing),
            "installed_tools": installed,
            "missing_tools": missing,
            "all_core_python_ready": all(
                all_tools.get(pkg, {}).get("available", False)
                for pkg in ["pikepdf", "pymupdf", "pypdf", "pillow", "python-docx", "openpyxl"]
            )
        }
