from .base import BaseExporter
from .csv_exporter import CsvExporter
from .json_exporter import JsonExporter
from .maltego_exporter import MaltegoExporter
from .markdown_exporter import MarkdownExporter
from .pdf_exporter import PdfExporter
from .stix_exporter import StixExporter

EXPORTERS: dict[str, type[BaseExporter]] = {
    e.format_name: e
    for e in [
        JsonExporter,
        CsvExporter,
        PdfExporter,
        MarkdownExporter,
        StixExporter,
        MaltegoExporter,
    ]
}

__all__ = [
    "BaseExporter",
    "CsvExporter",
    "EXPORTERS",
    "JsonExporter",
    "MaltegoExporter",
    "MarkdownExporter",
    "PdfExporter",
    "StixExporter",
]
