import unittest
import pandas as pd
from monitor import collect_process_data, build_process_dataframe
from analyzer import ProcessAnalyzer

class TestPPIDX(unittest.TestCase):
    def test_collect_data(self):
        data = collect_process_data()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0, "Should collect at least one process")
        first = data[0]
        self.assertIn('pid', first)
        self.assertIn('ppid', first)
        self.assertIn('name', first)

    def test_analyzer_logic(self):
        # Create mock data
        mock_data = [
            # Normal
            {'pid': 100, 'ppid': 1, 'name': 'systemd', 'username': 'root', 'status': 'sleeping', 'cpu_percent': 0.1, 'memory_percent': 0.1, 'exe': '/usr/bin/systemd', 'num_children': 5},
            # Zombie
            {'pid': 200, 'ppid': 100, 'name': 'defunct_proc', 'username': 'user', 'status': 'zombie', 'cpu_percent': 0.0, 'memory_percent': 0.0, 'exe': '', 'num_children': 0},
            # High CPU
            {'pid': 300, 'ppid': 100, 'name': 'crypto_miner', 'username': 'user', 'status': 'running', 'cpu_percent': 95.0, 'memory_percent': 10.0, 'exe': '/tmp/miner', 'num_children': 0},
            # Fork Bomb
            {'pid': 400, 'ppid': 100, 'name': 'fork_bomb', 'username': 'user', 'status': 'running', 'cpu_percent': 10.0, 'memory_percent': 10.0, 'exe': '/bin/bash', 'num_children': 100},
        ]
        
        df = pd.DataFrame(mock_data)
        analyzer = ProcessAnalyzer(high_cpu_threshold=80, max_children=50)
        risky_df = analyzer.analyze(df)
        
        self.assertFalse(risky_df.empty, "Should detect risky processes")
        
        # Check assertions
        zombie = risky_df[risky_df['pid'] == 200].iloc[0]
        self.assertIn("Zombie Process", zombie['flags'])
        
        miner = risky_df[risky_df['pid'] == 300].iloc[0]
        self.assertIn("High CPU Usage", miner['flags'])
        self.assertIn("Suspicious Executable Path", miner['flags']) # mocked /tmp

        forker = risky_df[risky_df['pid'] == 400].iloc[0]
        self.assertIn("Excessive Child Processes", forker['flags'])

if __name__ == '__main__':
    unittest.main()
