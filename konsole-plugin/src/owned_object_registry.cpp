// SPDX-License-Identifier: GPL-2.0-or-later
#include "owned_object_registry.h"

#include <QtAlgorithms>

namespace OpenCodeBeacon
{
OwnedObjectRegistry::~OwnedObjectRegistry()
{
    clear();
}

bool OwnedObjectRegistry::contains(const QObject *owner) const
{
    return m_objects.contains(owner);
}

void OwnedObjectRegistry::insert(const QObject *owner, QObject *object)
{
    Q_ASSERT(owner != nullptr);
    Q_ASSERT(object != nullptr);
    Q_ASSERT(!m_objects.contains(owner));
    m_objects.insert(owner, object);
}

void OwnedObjectRegistry::removeOwner(const QObject *owner)
{
    delete m_objects.take(owner);
}

void OwnedObjectRegistry::clear()
{
    qDeleteAll(m_objects);
    m_objects.clear();
}
}
