import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import build_ios


def make_ipa(path, prefix):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(prefix + 'Info.plist', b'plist')
        archive.writestr(prefix + 'Runner', b'binary')


class IPAPayloadTests(unittest.TestCase):
    def test_rejects_ipa_without_payload_directory(self):
        # 复现用户报的故障：顶层直接是 Runner.app/，安装工具找不到 Payload/。
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / 'broken.ipa'
            make_ipa(ipa, 'Runner.app/')
            with self.assertRaisesRegex(SystemExit, '缺少 Payload/Runner.app/'):
                build_ios.assert_ipa_payload(ipa, Path('Runner.app'))

    def test_rejects_payload_without_info_plist(self):
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / 'broken.ipa'
            with zipfile.ZipFile(ipa, 'w') as archive:
                archive.writestr('Payload/Runner.app/Runner', b'binary')
            with self.assertRaisesRegex(SystemExit, 'Info.plist'):
                build_ios.assert_ipa_payload(ipa, Path('Runner.app'))

    def test_accepts_standard_ipa(self):
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / 'good.ipa'
            make_ipa(ipa, 'Payload/Runner.app/')
            build_ios.assert_ipa_payload(ipa, Path('Runner.app'))

    def test_unsigned_ipa_is_packed_with_keep_parent(self):
        # 锁住根因：ditto 漏掉 --keepParent 会把 Payload 这层压没。
        # 假 ditto 按该参数模拟真实结构，让 assert_ipa_payload 能行为化地抓到 bug。
        ditto_calls = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'pubspec.yaml').write_text('version: 0.2.76+83\n', encoding='utf-8')
            application = root / 'build' / 'ios' / 'iphoneos' / 'Runner.app'
            application.mkdir(parents=True)
            (application / 'Info.plist').write_bytes(b'plist')

            # 忠实模拟 ditto：带 --keepParent 时保留 Payload/ 层，否则只压目录内容。
            # 这样生产代码一旦漏掉 --keepParent，assert_ipa_payload 会真的抛异常。
            def fake_run(arguments, **kwargs):
                if arguments[0] != 'ditto':
                    return
                ditto_calls.append(arguments)
                target = Path(arguments[-1])
                keep_parent = '--keepParent' in arguments
                # 无 --keepParent 时 ditto 只压 Payload 的内容，Payload/ 这层会消失。
                prefix = ('Payload/' if keep_parent else '') + 'Runner.app/' \
                    if target.suffix == '.ipa' else 'Runner.app/'
                with zipfile.ZipFile(target, 'w') as archive:
                    archive.writestr(prefix + 'Info.plist', b'plist')
                    archive.writestr(prefix + 'Runner', b'binary')

            with mock.patch.object(build_ios, 'root', root), \
                    mock.patch.object(build_ios, 'build_core'), \
                    mock.patch.object(build_ios, 'run', side_effect=fake_run), \
                    mock.patch('shutil.which', return_value='/tools/flutter'), \
                    mock.patch.object(subprocess, 'check_output', return_value='_DuanjuRequest\n_DuanjuFree\n'), \
                    mock.patch.object(sys, 'argv', ['build_ios.py']):
                build_ios.main()

        ipa_calls = [call for call in ditto_calls if str(call[-1]).endswith('.ipa')]
        self.assertEqual(len(ipa_calls), 1)
        self.assertIn('--keepParent', ipa_calls[0])


if __name__ == '__main__':
    unittest.main()
