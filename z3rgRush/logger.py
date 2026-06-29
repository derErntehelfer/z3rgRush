import logging
import warnings
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.highlighter import NullHighlighter  # <--- NEW IMPORT

# ==============================================================================
# SUBDUED MONOCHROMATIC THEME ("Cool Slate")
# ==============================================================================
cool_slate_theme = Theme(
    {
        # --- Logging Levels ---
        "logging.level.debug": "dim #5C7A99",
        "logging.level.info": "#7A98B5",
        "logging.level.warning": "#99B3CC",
        "logging.level.error": "#B8CCE0",
        "logging.level.critical": "bold #D6E5F3",
        # --- Progress Bar ---
        "progress.description": "#7A98B5",
        "progress.spinner": "#99B3CC",
        "progress.bar.back": "dim #3D5266",
        "progress.bar.complete": "#7A98B5",
        "progress.percentage": "#8CA8C4",
        # --- General Semantic Styles ---
        "info": "#7A98B5",
        "warning": "#99B3CC",
        "danger": "#B8CCE0",
        "error": "#B8CCE0",
        "success": "#8CA8C4",
        # --- Data Representation (for dicts, lists, tracebacks) ---
        "repr.number": "#8CA8C4",
        "repr.string": "#7A98B5",
        "repr.bool_true": "#99B3CC",
        "repr.bool_false": "dim #5C7A99",
        "repr.url": "underline #99B3CC",
        "repr.none": "dim #5C7A99",
        # --- Tracebacks ---
        "traceback.border": "#3D5266",
        "traceback.title": "#B8CCE0",
        "traceback.text": "#7A98B5",
    }
)

# Single shared Console instance for the entire application
# highlighter=NullHighlighter() disables automatic coloring in console.print() calls
console = Console(theme=cool_slate_theme, highlighter=NullHighlighter())


class StemLogFilter(logging.Filter):
    """
    stem sometimes internally sets its child loggers to DEBUG,
    bypassing standard level configurations. This filter drops them.
    """

    def filter(self, record):
        if record.name.startswith("stem") and record.levelno < logging.WARNING:
            return False
        return True


class StemSocketErrorFilter(logging.Filter):
    """Filter to suppress stem SocketClosed errors during shutdown."""

    def filter(self, record):
        msg = record.getMessage()
        if "Error while receiving a control message" in msg and "SocketClosed" in msg:
            return False
        return True


def setup_logging(verbose=False, log_file=None):
    log_level = logging.DEBUG if verbose else logging.INFO

    rich_handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        markup=False,
        show_time=False,
        show_path=False,
        highlighter=NullHighlighter(),
    )

    # Add filters to suppress stem noise
    rich_handler.addFilter(StemLogFilter())
    rich_handler.addFilter(StemSocketErrorFilter())

    logging.basicConfig(
        level=log_level,
        format="%(name)s | %(message)s",
        datefmt="[%X]",
        handlers=[rich_handler],
    )

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        file_handler.addFilter(StemLogFilter())
        file_handler.addFilter(StemSocketErrorFilter())
        logging.getLogger().addHandler(file_handler)

    # Suppress other noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Force stem to propagate so our filters can catch it
    stem_logger = logging.getLogger("stem")
    stem_logger.handlers.clear()
    stem_logger.propagate = True

    warnings.filterwarnings("ignore")

    return logging.getLogger("z3rgRush")


logger = setup_logging()
