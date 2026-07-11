import 'package:flutter/widgets.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';
import 'package:manyui_hooks/manyui_hooks.dart';
import 'package:manyui_riverpod/manyui_riverpod.dart';

import '../api/manytier_client.dart';
import '../api/token_discovery.dart';
import '../connections/connections_dialog.dart';
import '../state/connection.dart';
import '../state/moons.dart';
import '../theme.dart';

/// Daemon-control dashboard: service status, joined networks, peers.
///
// TODO(manytier): controller UI (/controller/network CRUD, member
// authorization) lands in a later phase.
class NetworksPage extends HookConsumerWidget {
  const NetworksPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final connection = ref.watch(daemonConnectionProvider);

    return MScaffold(
      header: Row(
        children: <Widget>[
          Text('ManyTier', style: theme.typography.title),
          const SizedBox(width: 12),
          _connectionBadge(connection),
          const Spacer(),
          MButton(
            variant: MButtonVariant.ghost,
            onPressed: () => showConnectionsDialog(context),
            semanticLabel: 'Connections',
            child: const Text('Connections'),
          ),
          MButton(
            variant: MButtonVariant.ghost,
            onPressed: () => ref.toggleMThemeMode(themeModeProvider),
            semanticLabel: 'Toggle theme',
            child: MIcon(
              ref.watchMThemeMode(themeModeProvider) == MThemeMode.dark
                  ? MIconData.sun
                  : MIconData.moon,
            ),
          ),
        ],
      ),
      body: switch (connection) {
        AsyncData<DaemonConnection>(:final value) => switch (value) {
          DaemonNotRunning() => const _CenteredCard(child: _NotRunningCard()),
          DaemonUnauthorized() => const _CenteredCard(
            child: _UnauthorizedCard(),
          ),
          DaemonConnected() => _Dashboard(connection: value),
        },
        AsyncError<DaemonConnection>(:final error) => _CenteredCard(
          child: _ErrorCard(error: error),
        ),
        _ => Center(
          child: Text(
            'Connecting to local service...',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          ),
        ),
      },
    );
  }

  Widget _connectionBadge(AsyncValue<DaemonConnection> connection) {
    return switch (connection) {
      AsyncData<DaemonConnection>(:final value) => switch (value) {
        DaemonNotRunning() => const MBadge(
          variant: MBadgeVariant.outline,
          child: Text('Service not running'),
        ),
        DaemonUnauthorized() => const MBadge(
          variant: MBadgeVariant.destructive,
          child: Text('Unauthorized'),
        ),
        DaemonConnected(:final status) => MBadge(
          child: Text('Connected ${status.address}'),
        ),
      },
      AsyncError<DaemonConnection>() => const MBadge(
        variant: MBadgeVariant.destructive,
        child: Text('Error'),
      ),
      _ => const MBadge(
        variant: MBadgeVariant.secondary,
        child: Text('Connecting...'),
      ),
    };
  }
}

/// Centers a single card (the not-running / unauthorized / error states).
class _CenteredCard extends StatelessWidget {
  const _CenteredCard({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: child,
        ),
      ),
    );
  }
}

class _NotRunningCard extends ConsumerWidget {
  const _NotRunningCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Service not running', style: theme.typography.headlineSmall),
            const SizedBox(height: 12),
            Text(
              'ManyTier could not reach the local control service. '
              'Start it in a terminal, then retry:',
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'manytier service --data-dir ~/.manytier',
              style: theme.typography.code,
            ),
            const SizedBox(height: 24),
            MButton(
              variant: MButtonVariant.outline,
              onPressed: () =>
                  ref.read(daemonConnectionProvider.notifier).refresh(),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

class _UnauthorizedCard extends HookConsumerWidget {
  const _UnauthorizedCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final token = useState('');
    final probed = probedTokenPaths();

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Unauthorized', style: theme.typography.headlineSmall),
            const SizedBox(height: 12),
            Text(
              'The service rejected the auth token. Paste the contents of '
              'authtoken.secret from the service data directory.',
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
            const SizedBox(height: 16),
            const MLabel('Auth token'),
            const SizedBox(height: 8),
            MTextField(
              placeholder: '48-character token',
              semanticLabel: 'Auth token',
              obscureText: true,
              onChanged: (value) => token.value = value,
            ),
            const SizedBox(height: 16),
            MButton(
              onPressed: token.value.trim().isEmpty
                  ? null
                  : () {
                      final settings = ref.read(connectionSettingsProvider);
                      ref
                          .read(connectionsControllerProvider)
                          .update(
                            settings.copyWith(manualToken: token.value.trim()),
                          );
                    },
              child: const Text('Use token'),
            ),
            if (probed.isNotEmpty) ...<Widget>[
              const SizedBox(height: 16),
              Text(
                'Probed for authtoken.secret at:',
                style: theme.typography.caption.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
              const SizedBox(height: 4),
              for (final String path in probed)
                Text(
                  path,
                  style: theme.typography.caption.copyWith(
                    color: theme.colors.mutedForeground,
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ErrorCard extends ConsumerWidget {
  const _ErrorCard({required this.error});

  final Object error;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Service error', style: theme.typography.headlineSmall),
            const SizedBox(height: 12),
            Text(
              '$error',
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.destructive,
              ),
            ),
            const SizedBox(height: 24),
            MButton(
              variant: MButtonVariant.outline,
              onPressed: () =>
                  ref.read(daemonConnectionProvider.notifier).refresh(),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}

/// The connected dashboard: networks + join on one side, status + peers on
/// the other (side by side at >= 900 px, stacked below that).
class _Dashboard extends StatelessWidget {
  const _Dashboard({required this.connection});

  final DaemonConnected connection;

  @override
  Widget build(BuildContext context) {
    final networksColumn = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        _NetworksSection(networks: connection.networks),
        const SizedBox(height: 16),
        const _JoinCard(),
      ],
    );
    final statusColumn = Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        _StatusCard(status: connection.status),
        const SizedBox(height: 16),
        _PeersSection(
          peers: connection.peers,
          latencyHistory: connection.peerLatencyHistory,
        ),
        const SizedBox(height: 16),
        const _MoonsSection(),
      ],
    );

    return LayoutBuilder(
      builder: (BuildContext context, BoxConstraints constraints) {
        final bool wide = constraints.maxWidth >= 900;
        return SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: wide
              ? Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Expanded(child: networksColumn),
                    const SizedBox(width: 16),
                    Expanded(child: statusColumn),
                  ],
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: <Widget>[
                    networksColumn,
                    const SizedBox(height: 16),
                    statusColumn,
                  ],
                ),
        );
      },
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.status});

  final ManyTierStatus status;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Row(
              children: <Widget>[
                Expanded(
                  child: Text('Status', style: theme.typography.headlineSmall),
                ),
                MBadge(
                  variant: status.online
                      ? MBadgeVariant.primary
                      : MBadgeVariant.outline,
                  child: Text(status.online ? 'Online' : 'Offline'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _kv(theme, 'Node address', status.address, code: true),
            const SizedBox(height: 8),
            _kv(theme, 'Version', status.version),
          ],
        ),
      ),
    );
  }

  Widget _kv(MThemeData theme, String key, String value, {bool code = false}) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.baseline,
      textBaseline: TextBaseline.alphabetic,
      children: <Widget>[
        Expanded(
          child: Text(
            key,
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          ),
        ),
        Text(
          value,
          style: code ? theme.typography.code : theme.typography.bodySmall,
        ),
      ],
    );
  }
}

class _NetworksSection extends StatelessWidget {
  const _NetworksSection({required this.networks});

  final List<ManyTierNetwork> networks;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text('Networks', style: theme.typography.headlineSmall),
        const SizedBox(height: 12),
        if (networks.isEmpty)
          Text(
            'No networks joined yet.',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          )
        else
          for (final ManyTierNetwork network in networks) ...<Widget>[
            _NetworkCard(network: network),
            const SizedBox(height: 12),
          ],
      ],
    );
  }
}

class _NetworkCard extends HookConsumerWidget {
  const _NetworkCard({required this.network});

  final ManyTierNetwork network;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final leaving = useState(false);
    final error = useState<String?>(null);

    Future<void> leave() async {
      final bool? confirmed = await showMDialog<bool>(
        context,
        builder: (BuildContext ctx) {
          final dialogTheme = MTheme.of(ctx);
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(
                'Leave network?',
                style: dialogTheme.typography.headlineSmall,
              ),
              const SizedBox(height: 8),
              Text(network.id, style: dialogTheme.typography.code),
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: <Widget>[
                  MButton(
                    variant: MButtonVariant.ghost,
                    onPressed: () => Navigator.of(ctx).pop(false),
                    child: const Text('Cancel'),
                  ),
                  const SizedBox(width: 8),
                  MButton(
                    variant: MButtonVariant.destructive,
                    onPressed: () => Navigator.of(ctx).pop(true),
                    child: const Text('Leave'),
                  ),
                ],
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;

      leaving.value = true;
      error.value = null;
      try {
        await ref.read(manyTierClientProvider).leaveNetwork(network.id);
        await ref.read(daemonConnectionProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        leaving.value = false;
      }
    }

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Row(
              children: <Widget>[
                Expanded(
                  child: Text(
                    network.name.isEmpty ? '(unnamed)' : network.name,
                    style: theme.typography.body,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                MBadge(
                  variant: network.status == 'OK'
                      ? MBadgeVariant.primary
                      : MBadgeVariant.secondary,
                  child: Text(network.status),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(network.id, style: theme.typography.code),
            if (network.assignedAddresses.isNotEmpty) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                network.assignedAddresses.join('  '),
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
            ],
            if (error.value != null) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                error.value!,
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.destructive,
                ),
              ),
            ],
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: <Widget>[
                MButton(
                  variant: MButtonVariant.destructive,
                  size: MButtonSize.sm,
                  onPressed: leaving.value ? null : leave,
                  child: Text(leaving.value ? 'Leaving...' : 'Leave'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _JoinCard extends HookConsumerWidget {
  const _JoinCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final controller = useMController<String>('');
    final networkId = useState('');
    final joining = useState(false);
    final error = useState<String?>(null);

    final bool valid = networkIdPattern.hasMatch(networkId.value.trim());

    Future<void> join() async {
      joining.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .joinNetwork(networkId.value.trim());
        await ref.read(daemonConnectionProvider.notifier).refresh();
        controller.value = '';
        networkId.value = '';
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        joining.value = false;
      }
    }

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Join a network', style: theme.typography.headlineSmall),
            const SizedBox(height: 16),
            const MLabel('Network ID'),
            const SizedBox(height: 8),
            MTextField(
              controller: controller,
              placeholder: '16-digit network ID',
              semanticLabel: 'Network ID',
              error: networkId.value.trim().isNotEmpty && !valid,
              onChanged: (value) => networkId.value = value,
              onSubmitted: (_) {
                if (valid && !joining.value) join();
              },
            ),
            if (error.value != null) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                error.value!,
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.destructive,
                ),
              ),
            ],
            const SizedBox(height: 16),
            MButton(
              onPressed: valid && !joining.value ? join : null,
              child: Text(joining.value ? 'Joining...' : 'Join'),
            ),
          ],
        ),
      ),
    );
  }
}

class _PeersSection extends StatelessWidget {
  const _PeersSection({required this.peers, required this.latencyHistory});

  final List<ManyTierPeer> peers;
  final Map<String, List<int>> latencyHistory;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text('Peers', style: theme.typography.headlineSmall),
        const SizedBox(height: 12),
        if (peers.isEmpty)
          Text(
            'No peers yet.',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          )
        else
          MCard(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  for (int i = 0; i < peers.length; i++) ...<Widget>[
                    if (i > 0) const MDivider(),
                    _PeerRow(
                      peer: peers[i],
                      latencyHistory:
                          latencyHistory[peers[i].address] ?? const <int>[],
                    ),
                  ],
                ],
              ),
            ),
          ),
      ],
    );
  }
}

class _PeerRow extends StatelessWidget {
  const _PeerRow({required this.peer, required this.latencyHistory});

  final ManyTierPeer peer;
  final List<int> latencyHistory;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Row(
        children: <Widget>[
          Expanded(child: Text(peer.address, style: theme.typography.code)),
          MBadge(
            variant: peer.role == 'ROOT'
                ? MBadgeVariant.secondary
                : MBadgeVariant.outline,
            child: Text(peer.role),
          ),
          const SizedBox(width: 12),
          _PeerLatencySparkline(
            peerAddress: peer.address,
            samples: latencyHistory,
          ),
          const SizedBox(width: 12),
          SizedBox(
            width: 72,
            child: Text(
              peer.latency < 0 ? '- ms' : '${peer.latency} ms',
              style: muted,
              textAlign: TextAlign.right,
            ),
          ),
          const SizedBox(width: 12),
          SizedBox(
            width: 72,
            child: Text(
              '${peer.paths.length} path${peer.paths.length == 1 ? '' : 's'}',
              style: muted,
              textAlign: TextAlign.right,
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerLatencySparkline extends StatelessWidget {
  const _PeerLatencySparkline({
    required this.peerAddress,
    required this.samples,
  });

  final String peerAddress;
  final List<int> samples;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    return Semantics(
      label: 'Latency trend for $peerAddress',
      value: _latencyTrendValue(samples),
      child: SizedBox(
        width: 84,
        height: 24,
        child: CustomPaint(
          painter: _PeerLatencySparklinePainter(
            samples: samples,
            lineColor: theme.colors.primary,
            mutedColor: theme.colors.mutedForeground.withValues(alpha: 0.35),
          ),
        ),
      ),
    );
  }

  String _latencyTrendValue(List<int> samples) {
    if (samples.isEmpty) return 'No latency samples';
    if (samples.length == 1) return '${samples.single} milliseconds';
    return '${samples.first} to ${samples.last} milliseconds';
  }
}

class _PeerLatencySparklinePainter extends CustomPainter {
  const _PeerLatencySparklinePainter({
    required this.samples,
    required this.lineColor,
    required this.mutedColor,
  });

  final List<int> samples;
  final Color lineColor;
  final Color mutedColor;

  @override
  void paint(Canvas canvas, Size size) {
    final Paint baselinePaint = Paint()
      ..color = mutedColor
      ..strokeWidth = 1
      ..style = PaintingStyle.stroke;
    final double centerY = size.height / 2;
    canvas.drawLine(
      Offset(0, centerY),
      Offset(size.width, centerY),
      baselinePaint,
    );

    if (samples.isEmpty) return;

    final Paint linePaint = Paint()
      ..color = lineColor
      ..strokeWidth = 2
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round
      ..style = PaintingStyle.stroke;
    final Paint dotPaint = Paint()
      ..color = lineColor
      ..style = PaintingStyle.fill;

    final int minSample = samples.reduce((int a, int b) => a < b ? a : b);
    final int maxSample = samples.reduce((int a, int b) => a > b ? a : b);
    final double range = (maxSample - minSample).toDouble();
    final double stepX = samples.length == 1
        ? 0
        : size.width / (samples.length - 1);

    Offset pointAt(int index) {
      final double normalized = range == 0
          ? 0.5
          : (samples[index] - minSample) / range;
      return Offset(
        samples.length == 1 ? size.width / 2 : stepX * index,
        size.height - normalized * size.height,
      );
    }

    if (samples.length == 1) {
      canvas.drawCircle(pointAt(0), 2.5, dotPaint);
      return;
    }

    final Path path = Path()..moveTo(pointAt(0).dx, pointAt(0).dy);
    for (int i = 1; i < samples.length; i++) {
      final Offset point = pointAt(i);
      path.lineTo(point.dx, point.dy);
    }
    canvas.drawPath(path, linePaint);
  }

  @override
  bool shouldRepaint(_PeerLatencySparklinePainter oldDelegate) {
    return samples != oldDelegate.samples ||
        lineColor != oldDelegate.lineColor ||
        mutedColor != oldDelegate.mutedColor;
  }
}

/// Read-only moon status + orbit/deorbit actions.
///
/// Moon *file generation* stays CLI-side (`manytier moon generate`); this UI
/// only surfaces currently-orbited moons and lets the user orbit an existing
/// moon by ID or deorbit one already in the list.
class _MoonsSection extends HookConsumerWidget {
  const _MoonsSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final moons = ref.watch(moonsProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Row(
          children: <Widget>[
            Expanded(
              child: Text('Moons', style: theme.typography.headlineSmall),
            ),
            MButton(
              variant: MButtonVariant.ghost,
              size: MButtonSize.sm,
              onPressed: () => ref.read(moonsProvider.notifier).refresh(),
              semanticLabel: 'Refresh moons',
              child: const Text('Refresh'),
            ),
          ],
        ),
        const SizedBox(height: 12),
        switch (moons) {
          AsyncData<List<Moon>>(:final value) =>
            value.isEmpty
                ? Text(
                    'Not orbiting any moons.',
                    style: theme.typography.bodySmall.copyWith(
                      color: theme.colors.mutedForeground,
                    ),
                  )
                : MCard(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 20,
                        vertical: 8,
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: <Widget>[
                          for (int i = 0; i < value.length; i++) ...<Widget>[
                            if (i > 0) const MDivider(),
                            _MoonRow(moon: value[i]),
                          ],
                        ],
                      ),
                    ),
                  ),
          AsyncError<List<Moon>>(:final error) => Text(
            '$error',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.destructive,
            ),
          ),
          _ => Text(
            'Loading moons…',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          ),
        },
        const SizedBox(height: 12),
        const _OrbitMoonCard(),
      ],
    );
  }
}

class _MoonRow extends HookConsumerWidget {
  const _MoonRow({required this.moon});

  final Moon moon;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final deorbiting = useState(false);
    final error = useState<String?>(null);

    Future<void> deorbit() async {
      final bool? confirmed = await showMDialog<bool>(
        context,
        builder: (BuildContext ctx) {
          final dialogTheme = MTheme.of(ctx);
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(
                'Deorbit moon?',
                style: dialogTheme.typography.headlineSmall,
              ),
              const SizedBox(height: 8),
              Text(
                'This may affect connectivity if this moon provides your '
                'only route to other members.',
                style: dialogTheme.typography.bodySmall.copyWith(
                  color: dialogTheme.colors.mutedForeground,
                ),
              ),
              const SizedBox(height: 8),
              Text(moon.id, style: dialogTheme.typography.code),
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: <Widget>[
                  MButton(
                    variant: MButtonVariant.ghost,
                    onPressed: () => Navigator.of(ctx).pop(false),
                    child: const Text('Cancel'),
                  ),
                  const SizedBox(width: 8),
                  MButton(
                    variant: MButtonVariant.destructive,
                    onPressed: () => Navigator.of(ctx).pop(true),
                    child: const Text('Deorbit'),
                  ),
                ],
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;

      deorbiting.value = true;
      error.value = null;
      try {
        await ref.read(manyTierClientProvider).deorbitMoon(moon.id);
        await ref.read(moonsProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        deorbiting.value = false;
      }
    }

    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          Row(
            children: <Widget>[
              Expanded(child: Text(moon.id, style: theme.typography.code)),
              MBadge(
                variant: MBadgeVariant.secondary,
                child: Text(
                  '${moon.roots.length} root${moon.roots.length == 1 ? '' : 's'}',
                ),
              ),
              const SizedBox(width: 8),
              MButton(
                variant: MButtonVariant.destructive,
                size: MButtonSize.sm,
                onPressed: deorbiting.value ? null : deorbit,
                child: Text(deorbiting.value ? 'Deorbiting...' : 'Deorbit'),
              ),
            ],
          ),
          if (moon.roots.isNotEmpty) ...<Widget>[
            const SizedBox(height: 4),
            Text(
              moon.roots
                  .map(
                    (MoonRoot r) => r.endpoints.isEmpty
                        ? r.address
                        : '${r.address} (${r.endpoints.join(', ')})',
                  )
                  .join('  '),
              style: muted,
            ),
          ],
          if (error.value != null) ...<Widget>[
            const SizedBox(height: 4),
            Text(
              error.value!,
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.destructive,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _OrbitMoonCard extends HookConsumerWidget {
  const _OrbitMoonCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final controller = useMController<String>('');
    final moonId = useState('');
    final orbiting = useState(false);
    final error = useState<String?>(null);

    final bool valid = networkIdPattern.hasMatch(moonId.value.trim());

    Future<void> orbit() async {
      orbiting.value = true;
      error.value = null;
      try {
        await ref.read(manyTierClientProvider).orbitMoon(moonId.value.trim());
        await ref.read(moonsProvider.notifier).refresh();
        controller.value = '';
        moonId.value = '';
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        orbiting.value = false;
      }
    }

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Orbit a moon', style: theme.typography.headlineSmall),
            const SizedBox(height: 16),
            const MLabel('Moon ID'),
            const SizedBox(height: 8),
            MTextField(
              controller: controller,
              placeholder: '16-digit moon ID',
              semanticLabel: 'Moon ID',
              error: moonId.value.trim().isNotEmpty && !valid,
              onChanged: (value) => moonId.value = value,
              onSubmitted: (_) {
                if (valid && !orbiting.value) orbit();
              },
            ),
            if (error.value != null) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                error.value!,
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.destructive,
                ),
              ),
            ],
            const SizedBox(height: 16),
            MButton(
              onPressed: valid && !orbiting.value ? orbit : null,
              child: Text(orbiting.value ? 'Orbiting...' : 'Orbit'),
            ),
          ],
        ),
      ),
    );
  }
}
