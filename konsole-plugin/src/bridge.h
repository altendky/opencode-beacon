// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <QDBusContext>
#include <QObject>
#include <QString>
#include <QStringList>

namespace Konsole
{
class ViewManager;
}

namespace OpenCodeBeacon
{
inline constexpr uint BridgeProtocolVersion = 1;
inline constexpr qsizetype MaximumActivationTokenSize = 4096;

QString bridgeObjectPath(int managerId);
bool validSessionId(int sessionId);
bool validActivationToken(const QString &token);

enum class ActivationOutcome {
    Activated,
    SessionNotOwned,
    SelectionFailed,
};

template<typename Target>
ActivationOutcome selectAndActivate(Target &target, const int sessionId, const QString &xdgActivationToken)
{
    if (!target.sessionList().contains(QString::number(sessionId))) {
        return ActivationOutcome::SessionNotOwned;
    }
    if (!target.selectSessionContainer(sessionId)) {
        return ActivationOutcome::SelectionFailed;
    }
    target.activationRequest(xdgActivationToken);
    return ActivationOutcome::Activated;
}

#ifndef BEACON_BRIDGE_POLICY_ONLY
class Bridge final : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.altendky.OpenCodeBeacon.KonsoleActivationBridge1")

public:
    explicit Bridge(Konsole::ViewManager *viewManager, QObject *parent = nullptr);
    ~Bridge() override;

    bool registerOnSessionBus();

public Q_SLOTS:
    Q_SCRIPTABLE uint protocolVersion() const;
    Q_SCRIPTABLE QStringList capabilities() const;
    Q_SCRIPTABLE bool activateSession(int sessionId, const QString &xdgActivationToken);

private:
    bool authorizeCaller();
    void sendError(const char *name, const QString &message);

    Konsole::ViewManager *const m_viewManager;
    const QString m_objectPath;
    bool m_registered = false;
};
#endif
}
