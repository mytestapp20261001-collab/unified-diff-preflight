import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("local_tool", HERE / "tool.py")
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)

class Tests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(HERE/'tool.py'), *map(str,args)], capture_output=True, text=True)
    def codes(self, *args):
        return [item['code'] for item in tool.audit(*args)['findings']]
    def test_cli_bad_args(self):
        result = self.cli('--unknown')
        self.assertEqual(result.returncode, 2); self.assertEqual(json.loads(result.stdout)['status'], 'error')
    def test_read_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'big'; path.write_text(' '*(tool.MAX_BYTES+1))
            with self.assertRaises(tool.BadInput): tool.read_text(path)
    def good(self): return (HERE/'examples/pass.diff').read_text()
    def test_pass(self): self.assertEqual(tool.audit(self.good())['status'],'pass')
    def test_findings(self):
        codes=self.codes((HERE/'examples/fail.diff').read_text())
        self.assertIn('unsafe_or_unsupported_path',codes); self.assertIn('hunk_count_mismatch',codes)
    def test_cli_examples(self):
        for name, expected in [('pass',0),('fail',1)]:
            result=self.cli(HERE/f'examples/{name}.diff')
            self.assertEqual(result.returncode,expected,result.stdout+result.stderr); json.loads(result.stdout)
    def test_create(self): self.assertEqual(tool.audit('--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n')['status'],'pass')
    def test_delete(self): self.assertEqual(tool.audit('--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n')['status'],'pass')
    def test_no_newline(self): self.assertEqual(tool.audit(self.good()+'\\ No newline at end of file\n')['status'],'pass')
    def test_misplaced_marker(self):
        with self.assertRaises(tool.BadInput): tool.audit('--- a/x\n+++ b/x\n@@ -1 +1 @@\n\\ No newline at end of file\n')
    def test_overlap(self): self.assertIn('overlapping_or_out_of_order_hunks',self.codes(self.good()+'@@ -2 +2 @@\n x\n'))
    def test_valid_multiple_hunks(self): self.assertEqual(tool.audit(self.good()+'@@ -10 +10 @@\n x\n')['status'],'pass')
    def test_gap(self): self.assertIn('inconsistent_hunk_gap',self.codes(self.good()+'@@ -10 +11 @@\n x\n'))
    def test_multi_file(self): self.assertEqual(tool.audit(self.good()+self.good().replace('demo.txt','other.txt'))['summary']['files'],2)
    def test_binary(self): self.assertIn('binary_patch_unsupported',self.codes('diff --git a/x b/x\nGIT binary patch\nliteral 3\nabc\n'))
    def test_quoted_path(self): self.assertIn('unsafe_or_unsupported_path',self.codes(self.good().replace('a/demo.txt','"a/demo.txt"')))
    def test_windows_escape(self): self.assertTrue(tool.unsafe_path('C:\\escape.txt'))
    def test_metadata(self): self.assertIn('metadata_operation_not_validated',self.codes('diff --git a/x b/y\nrename from x\nrename to y\n'))
    def test_combined_rejected(self):
        with self.assertRaises(tool.BadInput): tool.audit('--- a/x\n+++ b/x\n@@@ -1 -1 +1 @@@\n')
    def test_empty(self): self.assertIn('no_file_sections',self.codes(''))
    def test_bad_cli(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.diff'; path.write_text('not a patch')
            result=self.cli(path); self.assertEqual(result.returncode,2); json.loads(result.stdout)

    def test_generated_standard_patches(self):
        import difflib
        import random
        rng = random.Random(712)
        for trial in range(100):
            old = [f'line {i}\n' for i in range(rng.randrange(80))]
            new = old[:]
            for _ in range(rng.randrange(1, 12)):
                at = rng.randrange(len(new)+1)
                if at < len(new) and rng.randrange(2): del new[at]
                else: new.insert(at, f'insert {trial}\n')
            patch = ''.join(difflib.unified_diff(old, new, fromfile='a/test.txt', tofile='b/test.txt', n=rng.randrange(4)))
            if patch: self.assertEqual(tool.audit(patch)['status'], 'pass', patch)

    def test_git_boundary_requires_new_text_headers(self):
        patch = '--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/g b/g\n@@ -2 +2 @@\n-old\n+new\n'
        with self.assertRaises(tool.BadInput):
            tool.audit(patch)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'missing-header.diff'; path.write_text(patch)
            result = self.cli(path)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'], 'error')

    def test_valid_git_multifile_resets_hunk_positions(self):
        patch = 'diff --git a/demo.txt b/demo.txt\nindex 1111111..2222222 100644\n' + self.good()
        patch += 'diff --git a/other.txt b/other.txt\nindex 3333333..4444444 100644\n' + self.good().replace('demo.txt', 'other.txt')
        result = tool.audit(patch)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['summary']['files'], 2)
        self.assertEqual(result['summary']['hunks'], 2)

    def test_git_boundary_finishes_empty_text_section_once(self):
        patch = '--- a/empty.txt\n+++ b/empty.txt\ndiff --git a/demo.txt b/demo.txt\n' + self.good()
        result = tool.audit(patch)
        unfinished = [f for f in result['findings'] if f['code'] == 'file_without_hunks']
        self.assertEqual(unfinished, [{'code':'file_without_hunks', 'file_index':0}])
        self.assertEqual(result['summary']['files'], 2)

    def test_git_metadata_only_after_text_is_not_pass(self):
        patch = self.good() + 'diff --git a/other.txt b/other.txt\nindex 1111111..2222222 100644\n'
        result = tool.audit(patch)
        self.assertEqual(result['status'], 'findings')
        self.assertEqual(self.codes(patch), ['file_without_text_headers'])
        self.assertEqual(result['summary']['files'], 1)
        self.assertEqual(result['summary']['hunks'], 1)

    def test_empty_git_section_before_next_is_reported(self):
        patch = 'diff --git a/empty.txt b/empty.txt\ndiff --git a/demo.txt b/demo.txt\n' + self.good()
        self.assertEqual(self.codes(patch), ['file_without_text_headers'])

    def test_git_binary_after_text_stays_unsupported(self):
        for binary in ('GIT binary patch\nliteral 3\nabc\n', 'Binary files a/bin and b/bin differ\n'):
            patch = self.good() + 'diff --git a/bin b/bin\n' + binary
            result = tool.audit(patch)
            self.assertEqual(self.codes(patch), ['binary_patch_unsupported'])
            self.assertEqual(result['summary']['files'], 1)
            self.assertEqual(result['summary']['hunks'], 1)

    def test_git_binary_then_valid_text_resets_state(self):
        patch = self.good() + 'diff --git a/bin b/bin\nGIT binary patch\nliteral 3\nabc\n'
        patch += 'diff --git a/other.txt b/other.txt\n' + self.good().replace('demo.txt', 'other.txt')
        result = tool.audit(patch)
        self.assertEqual(self.codes(patch), ['binary_patch_unsupported'])
        self.assertEqual(result['summary']['files'], 2)
        self.assertEqual(result['summary']['hunks'], 2)

    def test_git_mode_only_after_text_reports_unvalidated(self):
        patch = self.good() + 'diff --git a/other.txt b/other.txt\nold mode 100644\nnew mode 100755\n'
        codes = self.codes(patch)
        self.assertEqual(codes.count('metadata_operation_not_validated'), 2)
        self.assertIn('file_without_text_headers', codes)

if __name__ == '__main__': unittest.main()
