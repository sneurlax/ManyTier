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
import '../state/controller_networks.dart';
import '../state/moons.dart';
import '../state/service_lifecycle.dart';
import '../state/service_registration.dart';
import '../theme.dart';

/// Daemon-control dashboard: service status, joined networks, peers.
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

class _NotRunningCard extends HookConsumerWidget {
  const _NotRunningCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final settings = ref.watch(connectionSettingsProvider);
    final lifecycle = ref.watch(serviceLifecycleProvider);
    final registration = ref.watch(serviceRegistrationProvider);
    final lifecycleController = ref.read(serviceLifecycleProvider.notifier);
    final registrationController = ref.read(
      serviceRegistrationProvider.notifier,
    );
    final unavailableReason = lifecycleController.unavailableReason(settings);
    final registrationUnavailableReason = registrationController
        .unavailableReason(settings);
    useEffect(() {
      Future<void>.microtask(
        () => ref.read(serviceRegistrationProvider.notifier).refresh(settings),
      );
      return null;
    }, <Object?>[settings.id, settings.host, settings.port]);

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
              'Start it from this app or in a terminal, then retry:',
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.mutedForeground,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              lifecycleController.commandPreview(settings),
              style: theme.typography.code,
            ),
            const SizedBox(height: 16),
            _LaunchAgentStatus(
              registration: registration,
              unavailableReason: registrationUnavailableReason,
            ),
            if (unavailableReason != null) ...<Widget>[
              const SizedBox(height: 12),
              Text(
                unavailableReason,
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.mutedForeground,
                ),
              ),
            ],
            if (lifecycle.error != null) ...<Widget>[
              const SizedBox(height: 12),
              Text(
                lifecycle.error!,
                style: theme.typography.bodySmall.copyWith(
                  color: theme.colors.destructive,
                ),
              ),
            ],
            const SizedBox(height: 24),
            Wrap(
              alignment: WrapAlignment.end,
              spacing: 8,
              runSpacing: 8,
              children: <Widget>[
                MButton(
                  variant: MButtonVariant.outline,
                  onPressed: () =>
                      ref.read(daemonConnectionProvider.notifier).refresh(),
                  child: const Text('Retry'),
                ),
                MButton(
                  onPressed:
                      lifecycle.starting ||
                          unavailableReason != null ||
                          lifecycle.startedService != null
                      ? null
                      : () async {
                          await ref
                              .read(serviceLifecycleProvider.notifier)
                              .start(settings);
                          await Future<void>.delayed(
                            const Duration(milliseconds: 250),
                          );
                          await ref
                              .read(daemonConnectionProvider.notifier)
                              .refresh();
                        },
                  child: Text(
                    lifecycle.starting ? 'Starting...' : 'Start service',
                  ),
                ),
                if (registration.installed)
                  MButton(
                    variant: MButtonVariant.destructive,
                    onPressed: registration.busy
                        ? null
                        : () async {
                            await ref
                                .read(serviceRegistrationProvider.notifier)
                                .uninstall();
                            await ref
                                .read(daemonConnectionProvider.notifier)
                                .refresh();
                          },
                    child: Text(
                      registration.uninstalling
                          ? 'Removing...'
                          : 'Remove login service',
                    ),
                  )
                else
                  MButton(
                    variant: MButtonVariant.outline,
                    onPressed:
                        registration.busy ||
                            registrationUnavailableReason != null
                        ? null
                        : () async {
                            await ref
                                .read(serviceRegistrationProvider.notifier)
                                .install(settings);
                            await Future<void>.delayed(
                              const Duration(milliseconds: 250),
                            );
                            await ref
                                .read(daemonConnectionProvider.notifier)
                                .refresh();
                          },
                    child: Text(
                      registration.installing
                          ? 'Installing...'
                          : 'Install at login',
                    ),
                  ),
              ],
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
        const _ManagedServiceCard(),
        const _SystemServiceCard(),
        const SizedBox(height: 16),
        _PeersSection(
          peers: connection.peers,
          latencyHistory: connection.peerLatencyHistory,
        ),
        const SizedBox(height: 16),
        const _ControllerSection(),
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

class _LaunchAgentStatus extends StatelessWidget {
  const _LaunchAgentStatus({
    required this.registration,
    required this.unavailableReason,
  });

  final ServiceRegistrationState registration;
  final String? unavailableReason;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );
    final error = registration.error;
    final snapshot = registration.snapshot;

    final String message;
    if (unavailableReason != null) {
      message = unavailableReason!;
    } else if (registration.loading) {
      message = 'Checking login service...';
    } else if (snapshot == null || !snapshot.installed) {
      message = 'Login service is not installed.';
    } else if (snapshot.loaded) {
      message = 'Login service is installed and loaded.';
    } else {
      message = 'Login service is installed but not loaded.';
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text(message, style: muted),
        if (snapshot?.installed ?? false) ...<Widget>[
          const SizedBox(height: 4),
          Text(snapshot!.plistPath, style: theme.typography.code),
        ],
        if (error != null) ...<Widget>[
          const SizedBox(height: 8),
          Text(
            error,
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.destructive,
            ),
          ),
        ],
      ],
    );
  }
}

class _ManagedServiceCard extends ConsumerWidget {
  const _ManagedServiceCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final lifecycle = ref.watch(serviceLifecycleProvider);
    final service = lifecycle.startedService;
    if (service == null) return const SizedBox.shrink();

    final theme = MTheme.of(context);
    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );

    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: MCard(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Expanded(
                    child: Text(
                      'Managed service',
                      style: theme.typography.headlineSmall,
                    ),
                  ),
                  MBadge(
                    variant: MBadgeVariant.secondary,
                    child: Text('PID ${service.pid}'),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(service.command, style: theme.typography.code),
              if (lifecycle.error != null) ...<Widget>[
                const SizedBox(height: 8),
                Text(
                  lifecycle.error!,
                  style: theme.typography.bodySmall.copyWith(
                    color: theme.colors.destructive,
                  ),
                ),
              ] else ...<Widget>[
                const SizedBox(height: 8),
                Text('Started by this app session.', style: muted),
              ],
              const SizedBox(height: 16),
              Wrap(
                alignment: WrapAlignment.end,
                spacing: 8,
                runSpacing: 8,
                children: <Widget>[
                  MButton(
                    variant: MButtonVariant.destructive,
                    size: MButtonSize.sm,
                    onPressed: lifecycle.canStop
                        ? () async {
                            await ref
                                .read(serviceLifecycleProvider.notifier)
                                .stop();
                            await ref
                                .read(daemonConnectionProvider.notifier)
                                .refresh();
                          }
                        : null,
                    child: Text(
                      lifecycle.stopping ? 'Stopping...' : 'Stop service',
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SystemServiceCard extends HookConsumerWidget {
  const _SystemServiceCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(connectionSettingsProvider);
    final registration = ref.watch(serviceRegistrationProvider);
    final snapshot = registration.snapshot;
    useEffect(() {
      Future<void>.microtask(
        () => ref.read(serviceRegistrationProvider.notifier).refresh(settings),
      );
      return null;
    }, <Object?>[settings.id, settings.host, settings.port]);

    if (snapshot == null || !snapshot.installed) {
      return const SizedBox.shrink();
    }

    final theme = MTheme.of(context);
    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );

    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: MCard(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Expanded(
                    child: Text(
                      'Login service',
                      style: theme.typography.headlineSmall,
                    ),
                  ),
                  MBadge(
                    variant: snapshot.loaded
                        ? MBadgeVariant.primary
                        : MBadgeVariant.secondary,
                    child: Text(snapshot.loaded ? 'Loaded' : 'Installed'),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(snapshot.plistPath, style: theme.typography.code),
              if (snapshot.command != null) ...<Widget>[
                const SizedBox(height: 8),
                Text(snapshot.command!, style: theme.typography.code),
              ],
              if (registration.error != null) ...<Widget>[
                const SizedBox(height: 8),
                Text(
                  registration.error!,
                  style: theme.typography.bodySmall.copyWith(
                    color: theme.colors.destructive,
                  ),
                ),
              ] else ...<Widget>[
                const SizedBox(height: 8),
                Text('LaunchAgent starts the service at login.', style: muted),
              ],
              const SizedBox(height: 16),
              Wrap(
                alignment: WrapAlignment.end,
                spacing: 8,
                runSpacing: 8,
                children: <Widget>[
                  MButton(
                    variant: MButtonVariant.destructive,
                    size: MButtonSize.sm,
                    onPressed: registration.busy
                        ? null
                        : () async {
                            await ref
                                .read(serviceRegistrationProvider.notifier)
                                .uninstall();
                            await ref
                                .read(daemonConnectionProvider.notifier)
                                .refresh();
                          },
                    child: Text(
                      registration.uninstalling
                          ? 'Removing...'
                          : 'Remove login service',
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
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

class _ControllerSection extends HookConsumerWidget {
  const _ControllerSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final controllerNetworks = ref.watch(controllerNetworksProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Row(
          children: <Widget>[
            Expanded(
              child: Text('Controller', style: theme.typography.headlineSmall),
            ),
            MButton(
              variant: MButtonVariant.ghost,
              size: MButtonSize.sm,
              onPressed: () =>
                  ref.read(controllerNetworksProvider.notifier).refresh(),
              semanticLabel: 'Refresh controller networks',
              child: const Text('Refresh'),
            ),
          ],
        ),
        const SizedBox(height: 12),
        switch (controllerNetworks) {
          AsyncData<List<ControllerNetworkDetail>>(:final value) =>
            value.isEmpty
                ? Text(
                    'No controller networks.',
                    style: theme.typography.bodySmall.copyWith(
                      color: theme.colors.mutedForeground,
                    ),
                  )
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: <Widget>[
                      for (final ControllerNetworkDetail detail
                          in value) ...<Widget>[
                        _ControllerNetworkCard(detail: detail),
                        const SizedBox(height: 12),
                      ],
                    ],
                  ),
          AsyncError<List<ControllerNetworkDetail>>(:final error) => Text(
            '$error',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.destructive,
            ),
          ),
          _ => Text(
            'Loading controller networks…',
            style: theme.typography.bodySmall.copyWith(
              color: theme.colors.mutedForeground,
            ),
          ),
        },
        const SizedBox(height: 12),
        const _CreateControllerNetworkCard(),
      ],
    );
  }
}

class _ControllerNetworkCard extends HookConsumerWidget {
  const _ControllerNetworkCard({required this.detail});

  final ControllerNetworkDetail detail;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final deleting = useState(false);
    final editing = useState(false);
    final error = useState<String?>(null);
    final network = detail.network;

    Future<void> edit() async {
      final ControllerNetworkUpdate? update =
          await showMDialog<ControllerNetworkUpdate>(
            context,
            builder: (BuildContext ctx) {
              return _EditControllerNetworkDialog(network: network);
            },
          );
      if (update == null) return;

      editing.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .updateControllerNetwork(network.id, update);
        await ref.read(controllerNetworksProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        editing.value = false;
      }
    }

    Future<void> delete() async {
      final bool? confirmed = await showMDialog<bool>(
        context,
        builder: (BuildContext ctx) {
          final dialogTheme = MTheme.of(ctx);
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(
                'Delete controller network?',
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
                    child: const Text('Delete'),
                  ),
                ],
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;

      deleting.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .deleteControllerNetwork(network.id);
        await ref.read(controllerNetworksProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        deleting.value = false;
      }
    }

    final muted = theme.typography.bodySmall.copyWith(
      color: theme.colors.mutedForeground,
    );

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
                  variant: network.private
                      ? MBadgeVariant.primary
                      : MBadgeVariant.outline,
                  child: Text(network.private ? 'Private' : 'Public'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(network.id, style: theme.typography.code),
            const SizedBox(height: 8),
            Wrap(
              spacing: 12,
              runSpacing: 4,
              children: <Widget>[
                Text('MTU ${network.mtu}', style: muted),
                Text('Multicast ${network.multicastLimit}', style: muted),
                Text(
                  '${detail.members.length} member${detail.members.length == 1 ? '' : 's'}',
                  style: muted,
                ),
              ],
            ),
            if (network.ipAssignmentPools.isNotEmpty) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                network.ipAssignmentPools
                    .map(
                      (ControllerIpPool p) =>
                          '${p.ipRangeStart}-${p.ipRangeEnd}',
                    )
                    .join('  '),
                style: muted,
              ),
            ],
            if (network.routes.isNotEmpty) ...<Widget>[
              const SizedBox(height: 4),
              Text(
                network.routes
                    .map(
                      (ControllerRoute r) =>
                          r.via == null ? r.target : '${r.target} via ${r.via}',
                    )
                    .join('  '),
                style: muted,
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
                  variant: MButtonVariant.outline,
                  size: MButtonSize.sm,
                  onPressed: editing.value ? null : edit,
                  child: Text(editing.value ? 'Saving...' : 'Edit'),
                ),
                const SizedBox(width: 8),
                MButton(
                  variant: MButtonVariant.destructive,
                  size: MButtonSize.sm,
                  onPressed: deleting.value ? null : delete,
                  child: Text(deleting.value ? 'Deleting...' : 'Delete'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            const MDivider(),
            const SizedBox(height: 8),
            Text('Members', style: theme.typography.body),
            if (detail.members.isEmpty) ...<Widget>[
              const SizedBox(height: 8),
              Text('No members.', style: muted),
            ] else
              for (int i = 0; i < detail.members.length; i++) ...<Widget>[
                if (i > 0) const MDivider(),
                _ControllerMemberRow(
                  network: network,
                  member: detail.members[i],
                ),
              ],
          ],
        ),
      ),
    );
  }
}

class _EditControllerNetworkDialog extends HookWidget {
  const _EditControllerNetworkDialog({required this.network});

  final ControllerNetwork network;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    final nameController = useMController<String>(network.name);
    final mtuController = useMController<String>(network.mtu.toString());
    final multicastController = useMController<String>(
      network.multicastLimit.toString(),
    );
    final name = useState(network.name);
    final mtu = useState(network.mtu.toString());
    final multicast = useState(network.multicastLimit.toString());
    final isPrivate = useState(network.private);
    final broadcast = useState(network.enableBroadcast);

    final int? parsedMtu = int.tryParse(mtu.value.trim());
    final int? parsedMulticast = int.tryParse(multicast.value.trim());
    final bool valid =
        parsedMtu != null && parsedMtu > 0 && parsedMulticast != null;

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text('Edit controller network', style: theme.typography.headlineSmall),
        const SizedBox(height: 16),
        const MLabel('Name'),
        const SizedBox(height: 8),
        MTextField(
          controller: nameController,
          placeholder: 'Network name',
          semanticLabel: 'Controller network name',
          onChanged: (value) => name.value = value,
        ),
        const SizedBox(height: 12),
        Row(
          children: <Widget>[
            Expanded(
              child: _DialogNumberField(
                label: 'MTU',
                controller: mtuController,
                value: mtu,
                invalid: parsedMtu == null || parsedMtu <= 0,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _DialogNumberField(
                label: 'Multicast limit',
                controller: multicastController,
                value: multicast,
                invalid: parsedMulticast == null,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        _SwitchRow(
          label: 'Private network',
          value: isPrivate.value,
          semanticLabel: 'Private network',
          onChanged: (value) => isPrivate.value = value,
        ),
        const SizedBox(height: 12),
        _SwitchRow(
          label: 'Broadcast',
          value: broadcast.value,
          semanticLabel: 'Broadcast',
          onChanged: (value) => broadcast.value = value,
        ),
        const SizedBox(height: 24),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: <Widget>[
            MButton(
              variant: MButtonVariant.ghost,
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            const SizedBox(width: 8),
            MButton(
              onPressed: !valid
                  ? null
                  : () => Navigator.of(context).pop(
                      ControllerNetworkUpdate(
                        name: name.value.trim(),
                        private: isPrivate.value,
                        mtu: parsedMtu,
                        multicastLimit: parsedMulticast,
                        enableBroadcast: broadcast.value,
                      ),
                    ),
              child: const Text('Save'),
            ),
          ],
        ),
      ],
    );
  }
}

class _DialogNumberField extends StatelessWidget {
  const _DialogNumberField({
    required this.label,
    required this.controller,
    required this.value,
    required this.invalid,
  });

  final String label;
  final MController<String> controller;
  final ValueNotifier<String> value;
  final bool invalid;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        MLabel(label),
        const SizedBox(height: 8),
        MTextField(
          controller: controller,
          placeholder: label,
          semanticLabel: label,
          keyboardType: TextInputType.number,
          error: value.value.trim().isNotEmpty && invalid,
          onChanged: (next) => value.value = next,
        ),
      ],
    );
  }
}

class _SwitchRow extends StatelessWidget {
  const _SwitchRow({
    required this.label,
    required this.value,
    required this.semanticLabel,
    required this.onChanged,
  });

  final String label;
  final bool value;
  final String semanticLabel;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    return Row(
      children: <Widget>[
        Expanded(child: Text(label, style: theme.typography.bodySmall)),
        MSwitch(
          initialValue: value,
          semanticLabel: semanticLabel,
          onChanged: onChanged,
        ),
      ],
    );
  }
}

class _ControllerMemberRow extends HookConsumerWidget {
  const _ControllerMemberRow({required this.network, required this.member});

  final ControllerNetwork network;
  final ControllerMember member;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final saving = useState(false);
    final error = useState<String?>(null);

    Future<void> toggleAuthorized() async {
      saving.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .updateControllerMember(
              network.id,
              member.id,
              ControllerMemberUpdate(authorized: !member.authorized),
            );
        await ref.read(controllerNetworksProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        saving.value = false;
      }
    }

    Future<void> editIps() async {
      final List<String>? ips = await showMDialog<List<String>>(
        context,
        builder: (BuildContext ctx) {
          return _EditMemberIpsDialog(member: member);
        },
      );
      if (ips == null) return;

      saving.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .updateControllerMember(
              network.id,
              member.id,
              ControllerMemberUpdate(ipAssignments: ips),
            );
        await ref.read(controllerNetworksProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        saving.value = false;
      }
    }

    Future<void> delete() async {
      final bool? confirmed = await showMDialog<bool>(
        context,
        builder: (BuildContext ctx) {
          final dialogTheme = MTheme.of(ctx);
          return Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(
                'Delete member?',
                style: dialogTheme.typography.headlineSmall,
              ),
              const SizedBox(height: 8),
              Text(member.id, style: dialogTheme.typography.code),
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
                    child: const Text('Delete'),
                  ),
                ],
              ),
            ],
          );
        },
      );
      if (confirmed != true) return;

      saving.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .deleteControllerMember(network.id, member.id);
        await ref.read(controllerNetworksProvider.notifier).refresh();
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        saving.value = false;
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
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Text(
                      member.name.isEmpty ? member.id : member.name,
                      style: theme.typography.bodySmall,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 2),
                    Text(member.id, style: theme.typography.code),
                  ],
                ),
              ),
              MBadge(
                variant: member.authorized
                    ? MBadgeVariant.primary
                    : MBadgeVariant.outline,
                child: Text(member.authorized ? 'Authorized' : 'Pending'),
              ),
            ],
          ),
          if (member.ipAssignments.isNotEmpty) ...<Widget>[
            const SizedBox(height: 6),
            Text(member.ipAssignments.join('  '), style: muted),
          ],
          if (error.value != null) ...<Widget>[
            const SizedBox(height: 6),
            Text(
              error.value!,
              style: theme.typography.bodySmall.copyWith(
                color: theme.colors.destructive,
              ),
            ),
          ],
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            alignment: WrapAlignment.end,
            children: <Widget>[
              MButton(
                variant: MButtonVariant.outline,
                size: MButtonSize.sm,
                onPressed: saving.value ? null : editIps,
                child: const Text('Edit IPs'),
              ),
              MButton(
                variant: member.authorized
                    ? MButtonVariant.outline
                    : MButtonVariant.primary,
                size: MButtonSize.sm,
                onPressed: saving.value ? null : toggleAuthorized,
                child: Text(member.authorized ? 'Deauthorize' : 'Authorize'),
              ),
              MButton(
                variant: MButtonVariant.destructive,
                size: MButtonSize.sm,
                onPressed: saving.value ? null : delete,
                child: const Text('Delete'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _EditMemberIpsDialog extends HookWidget {
  const _EditMemberIpsDialog({required this.member});

  final ControllerMember member;

  @override
  Widget build(BuildContext context) {
    final theme = MTheme.of(context);
    final controller = useMController<String>(member.ipAssignments.join('\n'));
    final value = useState(member.ipAssignments.join('\n'));

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text('Edit member IPs', style: theme.typography.headlineSmall),
        const SizedBox(height: 16),
        const MLabel('IP assignments'),
        const SizedBox(height: 8),
        MTextField(
          controller: controller,
          placeholder: 'IP assignments',
          semanticLabel: 'IP assignments',
          minLines: 3,
          maxLines: 5,
          onChanged: (next) => value.value = next,
        ),
        const SizedBox(height: 24),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: <Widget>[
            MButton(
              variant: MButtonVariant.ghost,
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            const SizedBox(width: 8),
            MButton(
              onPressed: () =>
                  Navigator.of(context).pop(_parseIpList(value.value)),
              child: const Text('Save'),
            ),
          ],
        ),
      ],
    );
  }
}

class _CreateControllerNetworkCard extends HookConsumerWidget {
  const _CreateControllerNetworkCard();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = MTheme.of(context);
    final addressController = useMController<String>('');
    final nameController = useMController<String>('');
    final address = useState('');
    final name = useState('');
    final creating = useState(false);
    final error = useState<String?>(null);

    final bool validAddress = nodeAddressPattern.hasMatch(address.value.trim());

    Future<void> create() async {
      creating.value = true;
      error.value = null;
      try {
        await ref
            .read(manyTierClientProvider)
            .createControllerNetwork(
              address.value.trim(),
              update: ControllerNetworkUpdate(
                name: name.value.trim(),
                private: true,
              ),
            );
        await ref.read(controllerNetworksProvider.notifier).refresh();
        addressController.value = '';
        nameController.value = '';
        address.value = '';
        name.value = '';
      } on ManyTierException catch (e) {
        error.value = e.message;
      } finally {
        creating.value = false;
      }
    }

    return MCard(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text(
              'Create controller network',
              style: theme.typography.headlineSmall,
            ),
            const SizedBox(height: 16),
            const MLabel('Controller address'),
            const SizedBox(height: 8),
            MTextField(
              controller: addressController,
              placeholder: '10-digit node address',
              semanticLabel: 'Controller address',
              error: address.value.trim().isNotEmpty && !validAddress,
              onChanged: (value) => address.value = value,
              onSubmitted: (_) {
                if (validAddress && !creating.value) create();
              },
            ),
            const SizedBox(height: 12),
            const MLabel('Name'),
            const SizedBox(height: 8),
            MTextField(
              controller: nameController,
              placeholder: 'Network name',
              semanticLabel: 'New controller network name',
              onChanged: (value) => name.value = value,
              onSubmitted: (_) {
                if (validAddress && !creating.value) create();
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
              onPressed: validAddress && !creating.value ? create : null,
              child: Text(creating.value ? 'Creating...' : 'Create'),
            ),
          ],
        ),
      ),
    );
  }
}

List<String> _parseIpList(String value) {
  return value
      .split(RegExp(r'[\s,]+'))
      .map((String part) => part.trim())
      .where((String part) => part.isNotEmpty)
      .toList();
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
