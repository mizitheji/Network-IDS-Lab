import logging
import yaml

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

def setup_logger():
    logger = logging.getLogger("IDS")

    if logger.handlers:
        return logger

    logger.setLevel(CONFIG["logging"]["level"])

    handler = logging.FileHandler(CONFIG["logging"]["file"])
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger
