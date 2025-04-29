# antivirus.py
class Antivirus:
    def __init__(self):
        # Define a simple bad signature (example)
        self.bad_signatures = [
            b'PAYLOAD2'  # Replace with your actual signature
        ]

    def check_packet(self, packet):
        """Check if the packet contains any known bad signatures."""
        payload = bytes(packet)  # Convert packet to bytes
        for signature in self.bad_signatures:
            if signature in payload:
                return True  # Malicious packet detected
        return False  # No malicious signature found
