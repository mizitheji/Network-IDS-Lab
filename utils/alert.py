from utils.logger import setup_logger

logger = setup_logger()

def send_alert(attack, src_ip, severity, description):
    msg = f"[{severity}] {attack} from {src_ip} - {description}"
    logger.warning(msg)
    print(msg)
