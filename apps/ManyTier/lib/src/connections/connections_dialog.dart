import 'package:flutter/widgets.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';
import 'package:manyui_hooks/manyui_hooks.dart';

import '../state/connection.dart';

/// Opens the saved-connections switcher dialog.
Future<void> showConnectionsDialog(BuildContext context) {
  return showMDialog<void>(
    context,
    builder: (BuildContext ctx) => const _ConnectionsDialogContent(),
  );
}

class _ConnectionsDialogContent extends HookConsumerWidget {
  const _ConnectionsDialogContent();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final connections = ref.watch(connectionsProvider);
    final activeId = ref.watch(activeConnectionIdProvider);
    final adding = useState(false);

    return MDialogContent(
      title: 'Connections',
      maxWidth: 420,
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          for (final SavedConnection c in connections)
            _ConnectionRow(connection: c, active: c.id == activeId),
          const SizedBox(height: 8),
          if (adding.value)
            _AddConnectionForm(onDone: () => adding.value = false)
          else
            MButton(
              variant: MButtonVariant.outline,
              onPressed: () => adding.value = true,
              child: const Text('Add connection'),
            ),
        ],
      ),
      actions: <Widget>[
        MButton(
          variant: MButtonVariant.ghost,
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

class _ConnectionRow extends HookConsumerWidget {
  const _ConnectionRow({required this.connection, required this.active});

  final SavedConnection connection;
  final bool active;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final connections = ref.watch(connectionsProvider);

    return MListTile(
      title: Text(connection.label),
      subtitle: Text('${connection.host}:${connection.port}'),
      selected: active,
      onTap: active
          ? null
          : () =>
                ref.read(connectionsControllerProvider).switchTo(connection.id),
      semanticLabel: 'Switch to ${connection.label}',
      trailing: connections.length > 1
          ? MButton(
              variant: MButtonVariant.ghost,
              size: MButtonSize.sm,
              semanticLabel: 'Forget ${connection.label}',
              onPressed: () async {
                final confirmed = await showMConfirmDialog(
                  context,
                  title: 'Forget connection?',
                  content: Builder(
                    builder: (BuildContext ctx) => Text(
                      connection.label,
                      style: MTheme.of(ctx).typography.code,
                    ),
                  ),
                  confirmLabel: 'Forget',
                  confirmVariant: MButtonVariant.destructive,
                );
                if (confirmed) {
                  ref.read(connectionsControllerProvider).forget(connection.id);
                }
              },
              child: MIcon(MIconData.close),
            )
          : null,
    );
  }
}

class _AddConnectionForm extends HookConsumerWidget {
  const _AddConnectionForm({required this.onDone});

  final VoidCallback onDone;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final labelController = useMController<String>('');
    final hostController = useMController<String>('127.0.0.1');
    final portController = useMController<String>('9993');
    final labelFocus = useFocusNode();
    final hostFocus = useFocusNode();
    final portFocus = useFocusNode();

    final label = useState('');
    final host = useState('127.0.0.1');
    final port = useState('9993');

    final int? parsedPort = int.tryParse(port.value.trim());
    final bool portInvalid = port.value.trim().isNotEmpty && parsedPort == null;
    final bool valid =
        label.value.trim().isNotEmpty &&
        host.value.trim().isNotEmpty &&
        parsedPort != null;

    void add() {
      if (!valid) return;
      ref
          .read(connectionsControllerProvider)
          .add(
            SavedConnection(
              id: '${DateTime.now().microsecondsSinceEpoch}',
              label: label.value.trim(),
              host: host.value.trim(),
              port: parsedPort,
            ),
          );
      onDone();
    }

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            MField(
              label: 'Label',
              focusNode: labelFocus,
              child: MTextField(
                focusNode: labelFocus,
                controller: labelController,
                placeholder: 'e.g. Home NAS',
                semanticLabel: 'Connection label',
                onChanged: (value) => label.value = value,
              ),
            ),
            const SizedBox(height: 12),
            MField(
              label: 'Host',
              focusNode: hostFocus,
              child: MTextField(
                focusNode: hostFocus,
                controller: hostController,
                placeholder: '127.0.0.1',
                semanticLabel: 'Host',
                onChanged: (value) => host.value = value,
              ),
            ),
            const SizedBox(height: 12),
            MField(
              label: 'Port',
              focusNode: portFocus,
              errorText: portInvalid ? 'Enter a numeric port.' : null,
              child: MTextField(
                focusNode: portFocus,
                controller: portController,
                placeholder: '9993',
                semanticLabel: 'Port',
                error: portInvalid,
                onChanged: (value) => port.value = value,
                onSubmitted: (_) => add(),
              ),
            ),
            const SizedBox(height: 16),
            MDialogActions(
              children: <Widget>[
                MButton(
                  variant: MButtonVariant.ghost,
                  onPressed: onDone,
                  child: const Text('Cancel'),
                ),
                MButton(
                  onPressed: valid ? add : null,
                  child: const Text('Add'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
