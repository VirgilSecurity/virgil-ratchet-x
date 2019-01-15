//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation

// TODO: Make thread-safe
@objc(VSRFileOneTimeKeysStorage) open class FileOneTimeKeysStorage: NSObject, OneTimeKeysStorage {
    private var oneTimeKeys: OneTimeKeys?
    private let fileSystem: FileSystem

    private struct OneTimeKeys: Codable {
        var oneTimeKeys: [OneTimeKey]
    }

    @objc public init(fileSystem: FileSystem) {
        self.fileSystem = fileSystem

        super.init()
    }

    private let queue = DispatchQueue(label: "FileOneTimeKeysStorageQueue")
    private var interactionCounter = 0

    public func startInteraction() {
        self.queue.sync {
            if self.interactionCounter > 0 {
                self.interactionCounter += 1
                return
            }

            guard self.oneTimeKeys == nil else {
                return
            }

            let data = try! self.fileSystem.readOneTimeKeysFile()

            if !data.isEmpty {
                self.oneTimeKeys = try! PropertyListDecoder().decode(OneTimeKeys.self, from: data)
            }
            else {
                self.oneTimeKeys = OneTimeKeys(oneTimeKeys: [])
            }

            self.interactionCounter = 1
        }
    }

    public func stopInteraction() {
        self.queue.sync {
            guard self.interactionCounter > 0 else {
                assertionFailure("interactionCounter should be > 0")
                return
            }

            self.interactionCounter -= 1

            if self.interactionCounter > 0 {
                return
            }

            guard let oneTimeKeys = self.oneTimeKeys else {
                assertionFailure("oneTimeKeys should not be nil")
                return
            }

            let data = try! PropertyListEncoder().encode(oneTimeKeys)

            try! self.fileSystem.writeOneTimeKeysFile(data: data)

            self.oneTimeKeys = nil
        }
    }

    public func storeKey(_ key: Data, withId id: Data) throws -> OneTimeKey {
        return try self.queue.sync {
            guard var oneTimeKeys = self.oneTimeKeys else {
                throw NSError()
            }

            guard !oneTimeKeys.oneTimeKeys.map({ $0.identifier }).contains(id) else {
                throw NSError()
            }

            let oneTimeKey = OneTimeKey(identifier: id, key: key, orphanedFrom: nil)
            oneTimeKeys.oneTimeKeys.append(oneTimeKey)
            self.oneTimeKeys = oneTimeKeys

            return oneTimeKey
        }
    }

    public func retrieveKey(withId id: Data) throws -> OneTimeKey {
        guard let oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }

        guard let oneTimeKey = oneTimeKeys.oneTimeKeys.first(where: { $0.identifier == id }) else {
            throw NSError()
        }

        return oneTimeKey
    }

    public func deleteKey(withId id: Data) throws {
        try self.queue.sync {
            guard var oneTimeKeys = self.oneTimeKeys else {
                throw NSError()
            }

            guard let index = oneTimeKeys.oneTimeKeys.firstIndex(where: { $0.identifier == id }) else {
                throw NSError()
            }

            oneTimeKeys.oneTimeKeys.remove(at: index)
            self.oneTimeKeys = oneTimeKeys
        }
    }

    public func retrieveAllKeys() throws -> [OneTimeKey] {
        guard let oneTimeKeys = self.oneTimeKeys else {
            throw NSError()
        }

        return oneTimeKeys.oneTimeKeys
    }

    public func markKeyOrphaned(startingFrom date: Date, keyId: Data) throws {
        try self.queue.sync {
            guard var oneTimeKeys = self.oneTimeKeys else {
                throw NSError()
            }

            guard let index = oneTimeKeys.oneTimeKeys.firstIndex(where: { $0.identifier == keyId }) else {
                throw NSError()
            }

            let oneTimeKey = oneTimeKeys.oneTimeKeys[index]

            guard oneTimeKey.orphanedFrom == nil else {
                throw NSError()
            }

            oneTimeKeys.oneTimeKeys[index] = OneTimeKey(identifier: oneTimeKey.identifier, key: oneTimeKey.key, orphanedFrom: date)
            self.oneTimeKeys = oneTimeKeys
        }
    }
}
