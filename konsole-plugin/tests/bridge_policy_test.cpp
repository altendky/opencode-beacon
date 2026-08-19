// SPDX-License-Identifier: GPL-2.0-or-later
#include "bridge.h"
#include "owned_object_registry.h"

#include <QTest>

namespace
{
class FakeActivationTarget
{
public:
    QStringList sessionList()
    {
        calls.append(QStringLiteral("list"));
        return sessions;
    }

    bool selectSessionContainer(const int sessionId)
    {
        calls.append(QStringLiteral("select:%1").arg(sessionId));
        if (!selectionSucceeds) {
            return false;
        }
        selectedContainerSession = sessionId;
        return true;
    }

    void activationRequest(const QString &token)
    {
        calls.append(QStringLiteral("activate:%1").arg(token));
    }

    QStringList sessions;
    QStringList calls;
    int selectedContainerSession = 0;
    int focusedSession = 0;
    bool selectionSucceeds = true;
};

class DestructionProbe final : public QObject
{
public:
    explicit DestructionProbe(int *destructions)
        : m_destructions(destructions)
    {
    }

    ~DestructionProbe() override
    {
        ++*m_destructions;
    }

private:
    int *const m_destructions;
};
}

class BridgePolicyTest final : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void exactObjectPaths()
    {
        QCOMPARE(OpenCodeBeacon::bridgeObjectPath(11),
                 QStringLiteral("/org/altendky/OpenCodeBeacon/KonsoleActivationBridge/v1/Windows/11"));
        QVERIFY(OpenCodeBeacon::bridgeObjectPath(0).isEmpty());
        QVERIFY(OpenCodeBeacon::bridgeObjectPath(-1).isEmpty());
    }

    void strictArguments()
    {
        QVERIFY(OpenCodeBeacon::validSessionId(1));
        QVERIFY(!OpenCodeBeacon::validSessionId(0));
        QVERIFY(OpenCodeBeacon::validActivationToken(QStringLiteral("wayland-token_1")));
        QVERIFY(!OpenCodeBeacon::validActivationToken(QString()));
        QVERIFY(!OpenCodeBeacon::validActivationToken(QStringLiteral("token\nsecond-line")));
        QVERIFY(!OpenCodeBeacon::validActivationToken(
            QString(OpenCodeBeacon::MaximumActivationTokenSize + 1, QLatin1Char('x'))));
    }

    void activationOrderingFailsClosed()
    {
        FakeActivationTarget missing;
        missing.sessions = {QStringLiteral("4")};
        QCOMPARE(OpenCodeBeacon::selectAndActivate(missing, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::SessionNotOwned);
        QCOMPARE(missing.calls, QStringList({QStringLiteral("list")}));

        FakeActivationTarget failedSelection;
        failedSelection.sessions = {QStringLiteral("7")};
        failedSelection.selectionSucceeds = false;
        QCOMPARE(OpenCodeBeacon::selectAndActivate(failedSelection, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::SelectionFailed);
        QCOMPARE(failedSelection.calls, QStringList({QStringLiteral("list"), QStringLiteral("select:7")}));

        FakeActivationTarget staleFocusedSession;
        staleFocusedSession.sessions = {QStringLiteral("7")};
        staleFocusedSession.selectedContainerSession = 4;
        staleFocusedSession.focusedSession = 7;
        staleFocusedSession.selectionSucceeds = false;
        QCOMPARE(OpenCodeBeacon::selectAndActivate(staleFocusedSession, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::SelectionFailed);
        QCOMPARE(staleFocusedSession.selectedContainerSession, 4);
        QCOMPARE(staleFocusedSession.focusedSession, 7);
        QCOMPARE(staleFocusedSession.calls, QStringList({QStringLiteral("list"), QStringLiteral("select:7")}));

        FakeActivationTarget activated;
        activated.sessions = {QStringLiteral("7")};
        QCOMPARE(OpenCodeBeacon::selectAndActivate(activated, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::Activated);
        QCOMPARE(activated.selectedContainerSession, 7);
        QCOMPARE(activated.calls,
                 QStringList({QStringLiteral("list"),
                               QStringLiteral("select:7"),
                               QStringLiteral("activate:token")}));
    }

    void hiddenTabSelectionDoesNotDependOnFocusedSession()
    {
        FakeActivationTarget hiddenTab;
        hiddenTab.sessions = {QStringLiteral("4"), QStringLiteral("7")};
        hiddenTab.selectedContainerSession = 4;
        hiddenTab.focusedSession = 4;

        QCOMPARE(OpenCodeBeacon::selectAndActivate(hiddenTab, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::Activated);
        QCOMPARE(hiddenTab.selectedContainerSession, 7);
        QCOMPARE(hiddenTab.focusedSession, 4);
        QCOMPARE(hiddenTab.calls,
                 QStringList({QStringLiteral("list"), QStringLiteral("select:7"), QStringLiteral("activate:token")}));
    }

    void inactiveWindowSelectionDoesNotRequireFocusUpdate()
    {
        FakeActivationTarget inactiveWindow;
        inactiveWindow.sessions = {QStringLiteral("7")};
        inactiveWindow.focusedSession = 4;

        QCOMPARE(OpenCodeBeacon::selectAndActivate(inactiveWindow, 7, QStringLiteral("token")),
                 OpenCodeBeacon::ActivationOutcome::Activated);
        QCOMPARE(inactiveWindow.selectedContainerSession, 7);
        QCOMPARE(inactiveWindow.focusedSession, 4);
        QCOMPARE(inactiveWindow.calls,
                 QStringList({QStringLiteral("list"), QStringLiteral("select:7"), QStringLiteral("activate:token")}));
    }

    void registryDestroysSynchronouslyAndHandlesOwnerRemoval()
    {
        int destructions = 0;
        QObject firstOwner;
        QObject secondOwner;
        OpenCodeBeacon::OwnedObjectRegistry registry;
        registry.insert(&firstOwner, new DestructionProbe(&destructions));
        registry.insert(&secondOwner, new DestructionProbe(&destructions));

        registry.removeOwner(&firstOwner);
        QCOMPARE(destructions, 1);
        QVERIFY(!registry.contains(&firstOwner));
        QVERIFY(registry.contains(&secondOwner));

        registry.clear();
        QCOMPARE(destructions, 2);
        QVERIFY(!registry.contains(&secondOwner));
    }
};

QTEST_GUILESS_MAIN(BridgePolicyTest)

#include "bridge_policy_test.moc"
