import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import netscan  # noqa: E402


class ParsePortsTest(unittest.TestCase):
    def test_lista_e_intervalo(self):
        self.assertEqual(netscan.parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_intervalo_invertido(self):
        self.assertEqual(netscan.parse_ports("5-3"), [3, 4, 5])

    def test_common(self):
        self.assertIn(443, netscan.parse_ports("common"))

    def test_porta_invalida(self):
        with self.assertRaises(ValueError):
            netscan.parse_ports("0,70000")


class HostsInNetworkTest(unittest.TestCase):
    def test_rede_24(self):
        hosts = netscan.hosts_in_network("192.168.1.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.254")

    def test_rede_demasiado_grande(self):
        with self.assertRaises(ValueError):
            netscan.hosts_in_network("10.0.0.0/8")


class CheckPortTest(unittest.TestCase):
    def test_porta_aberta_e_fechada(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        t = threading.Thread(target=lambda: server.accept(), daemon=True)
        t.start()
        try:
            self.assertTrue(netscan.check_port("127.0.0.1", port))
        finally:
            server.close()
        self.assertFalse(netscan.check_port("127.0.0.1", port, timeout=0.3))


if __name__ == "__main__":
    unittest.main()
