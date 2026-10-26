import unittest

from check_event_name_contracts import enum_names, literal_issues


class EventNameContractTests(unittest.TestCase):
    names = {"TcpIpRecv", "TcpIpSend", "Read"}

    def test_old_inbound_array_is_flagged(self):
        self.assertTrue(literal_issues('new List<string> { "TcpIp/Recv" };', self.names))

    def test_unknown_network_name_is_flagged(self):
        self.assertTrue(literal_issues("network_activity = 'tcpiprecvv'", self.names, sql=True))

    def test_direct_sql_match_is_flagged_even_for_current_spelling(self):
        self.assertTrue(literal_issues("ipevent = 'TcpIpRecv'", self.names, sql=True))

    def test_canonical_sql_match_is_allowed(self):
        self.assertFalse(literal_issues("network_activity = 'tcpiprecv'", self.names, sql=True))

    def test_non_network_activity_typo_is_flagged(self):
        self.assertTrue(literal_issues('msg.ActivityType.ToString() == "Readd"', self.names))

    def test_live_enum_parser(self):
        self.assertEqual({"Read", "TcpIpRecv"}, enum_names("public enum ActivityTypeEnum { Read, TcpIpRecv }"))

    def test_network_gate_does_not_hide_broader_audit_finding(self):
        source = 'd.ActivityType == "STOP"'
        names = self.names | {"Stop"}
        self.assertTrue(literal_issues(source, names))
        self.assertFalse(literal_issues(source, names, network_only=True))


if __name__ == "__main__":
    unittest.main()
