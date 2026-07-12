import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:manytier_app/src/state/service_process.dart';
import 'package:manytier_app/src/state/service_registration_io.dart';

void main() {
  test(
    'Launchd registrar writes and removes a user LaunchAgent plist',
    () async {
      final temp = await Directory.systemTemp.createTemp(
        'manytier-launchd-test-',
      );
      addTearDown(() async {
        if (await temp.exists()) {
          await temp.delete(recursive: true);
        }
      });

      final binDir = Directory('${temp.path}/bin');
      await binDir.create();
      final binary = File('${binDir.path}/manytier');
      await binary.writeAsString('#!/bin/sh\n');

      final launchctlCalls = <List<String>>[];
      final registrar = LaunchdManyTierServiceRegistrar(
        environment: <String, String>{
          'HOME': temp.path,
          'PATH': binDir.path,
          'UID': '501',
        },
        processRunner: (String executable, List<String> arguments) async {
          if (executable == 'launchctl') {
            launchctlCalls.add(<String>[executable, ...arguments]);
          }
          return ProcessResult(1, 0, '', '');
        },
      );

      final snapshot = await registrar.install(
        ManyTierServiceStartRequest(
          apiPort: 4242,
          udpPort: 9993,
          dataDir: '${temp.path}/many & tier',
        ),
      );

      final plist = File(snapshot.plistPath);
      expect(await plist.exists(), isTrue);
      final contents = await plist.readAsString();
      expect(contents, contains('<key>ProgramArguments</key>'));
      expect(contents, contains('<string>${binary.path}</string>'));
      expect(contents, contains('<string>--api-port</string>'));
      expect(contents, contains('<string>4242</string>'));
      expect(contents, contains('many &amp; tier'));
      expect(snapshot.installed, isTrue);
      expect(snapshot.loaded, isTrue);
      expect(snapshot.command, contains('--api-port 4242'));
      expect(launchctlCalls, hasLength(3));
      expect(launchctlCalls[0], <String>[
        'launchctl',
        'bootout',
        'gui/501',
        '${temp.path}/Library/LaunchAgents/com.manymath.manytier.service.plist',
      ]);
      expect(launchctlCalls[1], <String>[
        'launchctl',
        'bootstrap',
        'gui/501',
        '${temp.path}/Library/LaunchAgents/com.manymath.manytier.service.plist',
      ]);
      expect(launchctlCalls[2], <String>[
        'launchctl',
        'print',
        'gui/501/com.manymath.manytier.service',
      ]);

      final removed = await registrar.uninstall();

      expect(removed.installed, isFalse);
      expect(await plist.exists(), isFalse);
      expect(launchctlCalls.last, <String>[
        'launchctl',
        'bootout',
        'gui/501',
        '${temp.path}/Library/LaunchAgents/com.manymath.manytier.service.plist',
      ]);
    },
    skip: !Platform.isMacOS,
  );
}
