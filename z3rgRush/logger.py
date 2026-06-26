import logging
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for z3rgRush
z3rg_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "circuit": "magenta",
        "payload": "blue",
    }
)

console = Console(theme=z3rg_theme)


def setup_logging(verbose=False, log_file=None):
    """
    Configure logging with rich handler

    Args:
        verbose: Enable debug level logging
        log_file: Optional file path for log output
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                tracebacks_show_locals=verbose,
                markup=True,
            )
        ],
    )

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logging.getLogger().addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("stem").setLevel(logging.WARNING)

    return logging.getLogger("z3rgRush")


# Global logger instance
logger = setup_logging()
