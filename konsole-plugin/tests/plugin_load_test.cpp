// SPDX-License-Identifier: GPL-2.0-or-later
#include <QJsonObject>
#include <QPluginLoader>
#include <QTest>

#include <KPluginFactory>

#include <pluginsystem/IKonsolePlugin.h>

class PluginLoadTest final : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void loadsWithExpectedMetadata()
    {
        QPluginLoader loader(QString::fromUtf8(BRIDGE_PLUGIN_PATH));
        const QJsonObject metadata = loader.metaData();
        QCOMPARE(metadata.value(QStringLiteral("IID")).toString(), QStringLiteral("org.kde.KPluginFactory"));
        const QJsonObject plugin = metadata.value(QStringLiteral("MetaData")).toObject().value(QStringLiteral("KPlugin")).toObject();
        QCOMPARE(plugin.value(QStringLiteral("Version")).toString(), QString::fromUtf8(EXPECTED_KONSOLE_VERSION));
        QCOMPARE(plugin.value(QStringLiteral("Name")).toString(), QStringLiteral("OpenCode Beacon Activation Bridge"));

        QVERIFY2(loader.load(), qPrintable(loader.errorString()));
        auto *factory = qobject_cast<KPluginFactory *>(loader.instance());
        QVERIFY2(factory != nullptr, qPrintable(loader.errorString()));
        auto *instance = factory->create<Konsole::IKonsolePlugin>();
        QVERIFY(instance != nullptr);
        delete instance;
        QVERIFY2(loader.unload(), qPrintable(loader.errorString()));
    }
};

QTEST_GUILESS_MAIN(PluginLoadTest)

#include "plugin_load_test.moc"
