import logging
import warnings
from rich.console import Console
from rich.logging import RichHandler

# Single shared Console instance for the entire application
console = Console()


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
    )

    # Add filters to suppress stem noise
    rich_handler.addFilter(StemLogFilter())
    rich_handler.addFilter(StemSocketErrorFilter())

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
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
