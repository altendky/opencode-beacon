// SPDX-License-Identifier: GPL-2.0-or-later
#include "bridge.h"

#include <QChar>

#include <algorithm>

namespace OpenCodeBeacon
{
QString bridgeObjectPath(const int managerId)
{
    if (managerId <= 0) {
        return {};
    }
    return QStringLiteral("/org/altendky/OpenCodeBeacon/KonsoleActivationBridge/v1/Windows/%1").arg(managerId);
}

bool validSessionId(const int sessionId)
{
    return sessionId > 0;
}

bool validActivationToken(const QString &token)
{
    return !token.isEmpty() && token.size() <= MaximumActivationTokenSize
        && std::all_of(token.cbegin(), token.cend(), [](const QChar character) {
               return character.unicode() >= 0x21 && character.unicode() <= 0x7e;
           });
}
}

#ifndef BEACON_BRIDGE_POLICY_ONLY
#include "MainWindow.h"
#include "ViewManager.h"
#include "session/Session.h"
#include "session/SessionController.h"
#include "terminalDisplay/TerminalDisplay.h"
#include "widgets/ViewContainer.h"

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusError>
#include <QDBusReply>

#include <unistd.h>

namespace OpenCodeBeacon
{
namespace
{
class ViewManagerActivationTarget
{
public:
    explicit ViewManagerActivationTarget(Konsole::ViewManager &viewManager)
        : m_viewManager(viewManager)
    {
    }

    QStringList sessionList()
    {
        return m_viewManager.sessionList();
    }

    bool selectSessionContainer(const int sessionId)
    {
        auto *container = m_viewManager.activeContainer();
        if (container == nullptr) {
            return false;
        }

        for (int index = 0; index < container->count(); ++index) {
            auto *tab = container->widget(index);
            if (tab == nullptr) {
                continue;
            }
            const auto displays = tab->findChildren<Konsole::TerminalDisplay *>();
            for (auto *display : displays) {
                auto *controller = display->sessionController();
                if (controller == nullptr) {
                    continue;
                }
                const auto session = controller->session();
                if (session.isNull() || session->sessionId() != sessionId) {
                    continue;
                }

                container->setCurrentWidget(tab);
                if (container->currentWidget() != tab || !tab->isAncestorOf(display)
                    || display->sessionController() != controller || controller->session() != session
                    || session->sessionId() != sessionId) {
                    return false;
                }

                display->setFocus(Qt::OtherFocusReason);
                return container->currentWidget() == tab && tab->isAncestorOf(display)
                    && display->sessionController() == controller && controller->session() == session
                    && session->sessionId() == sessionId;
            }
        }
        return false;
    }

    void activationRequest(const QString &xdgActivationToken)
    {
        m_viewManager.activationRequest(xdgActivationToken);
    }

private:
    Konsole::ViewManager &m_viewManager;
};
}

Bridge::Bridge(Konsole::ViewManager *viewManager, QObject *parent)
    : QObject(parent)
    , m_viewManager(viewManager)
    , m_objectPath(bridgeObjectPath(viewManager == nullptr ? 0 : viewManager->managerId()))
{
}

Bridge::~Bridge()
{
    if (m_registered) {
        QDBusConnection::sessionBus().unregisterObject(m_objectPath);
    }
}

bool Bridge::registerOnSessionBus()
{
    if (m_viewManager == nullptr || m_objectPath.isEmpty() || m_registered) {
        return false;
    }
    m_registered = QDBusConnection::sessionBus().registerObject(
        m_objectPath, this, QDBusConnection::ExportScriptableSlots);
    return m_registered;
}

uint Bridge::protocolVersion() const
{
    return BridgeProtocolVersion;
}

QStringList Bridge::capabilities() const
{
    return {QStringLiteral("activate-session-with-xdg-token")};
}

bool Bridge::activateSession(const int sessionId, const QString &xdgActivationToken)
{
    if (!authorizeCaller()) {
        return false;
    }
    if (!validSessionId(sessionId) || !validActivationToken(xdgActivationToken)) {
        sendError("org.freedesktop.DBus.Error.InvalidArgs", QStringLiteral("Invalid session ID or activation token"));
        return false;
    }

    ViewManagerActivationTarget target(*m_viewManager);
    switch (selectAndActivate(target, sessionId, xdgActivationToken)) {
    case ActivationOutcome::SessionNotOwned:
        sendError("org.altendky.OpenCodeBeacon.Error.SessionNotOwned",
                  QStringLiteral("The session is not owned by this Konsole window"));
        return false;
    case ActivationOutcome::SelectionFailed:
        sendError("org.altendky.OpenCodeBeacon.Error.SelectionFailed",
                  QStringLiteral("Konsole did not select the requested session"));
        return false;
    case ActivationOutcome::Activated:
        return true;
    }
    return false;
}

bool Bridge::authorizeCaller()
{
    if (!calledFromDBus()) {
        sendError("org.freedesktop.DBus.Error.AccessDenied", QStringLiteral("D-Bus invocation required"));
        return false;
    }
    auto *interface = connection().interface();
    const QDBusReply<uint> callerUid = interface == nullptr
        ? QDBusReply<uint>(QDBusError(QDBusError::Failed, QStringLiteral("No bus interface")))
        : interface->serviceUid(message().service());
    if (!callerUid.isValid() || callerUid.value() != static_cast<uint>(geteuid())) {
        sendError("org.freedesktop.DBus.Error.AccessDenied", QStringLiteral("Caller UID does not match Konsole"));
        return false;
    }
    return true;
}

void Bridge::sendError(const char *name, const QString &errorMessage)
{
    if (calledFromDBus()) {
        sendErrorReply(QString::fromLatin1(name), errorMessage);
    }
}
}
#endif
