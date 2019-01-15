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
import VirgilSDK

@objc(VSRKeychainLongTermKeysStorage) open class KeychainLongTermKeysStorage: NSObject, LongTermKeysStorage {
    private let keychainWrapper: KeychainStorageWrapper

    @objc public init(identity: String) throws {
        let params = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: params)
        self.keychainWrapper = KeychainStorageWrapper(identity: identity,
                                                      prefix: "LTK",
                                                      keychainStorage: keychainStorage)

        super.init()
    }

    private static let outdatedKey = "OD"

    private func makeMeta(outdated: Date) -> [String: String] {
        return [KeychainLongTermKeysStorage.outdatedKey: String(Int(outdated.timeIntervalSince1970))]
    }

    private func parseMeta(_ meta: [String: String]?) -> Date? {
        guard let meta = meta,
            let dateStr = meta[KeychainLongTermKeysStorage.outdatedKey],
            let dateTimestamp = Int(dateStr) else {
                return nil
        }

        return Date(timeIntervalSince1970: TimeInterval(dateTimestamp))
    }

    private func mapEntry(_ entry: KeychainEntry) throws -> LongTermKey {
        guard let id = Data(base64Encoded: entry.name) else {
            throw NSError()
        }

        return LongTermKey(identifier: id,
                           key: entry.data,
                           creationDate: entry.creationDate,
                           outdatedFrom: self.parseMeta(entry.meta))
    }

    public func storeKey(_ key: Data, withId id: Data) throws -> LongTermKey {
        let entry = try self.keychainWrapper.store(data: key, withName: id.base64EncodedString(), meta: [:])

        return try self.mapEntry(entry)
    }

    public func retrieveKey(withId id: Data) throws -> LongTermKey {
        let entry = try self.keychainWrapper.retrieveEntry(withName: id.base64EncodedString())

        return try self.mapEntry(entry)
    }

    public func deleteKey(withId id: Data) throws {
        try self.keychainWrapper.deleteEntry(withName: id.base64EncodedString())
    }

    public func retrieveAllKeys() throws -> [LongTermKey] {
        return try self.keychainWrapper.retrieveAllEntries().map(self.mapEntry)
    }

    public func markKeyOutdated(startingFrom date: Date, keyId: Data) throws {
        let entry = try self.keychainWrapper.retrieveEntry(withName: keyId.base64EncodedString())

        guard self.parseMeta(entry.meta) == nil else {
            throw NSError()
        }

        try self.keychainWrapper.updateEntry(withName: keyId.base64EncodedString(),
                                             data: entry.data,
                                             meta: self.makeMeta(outdated: date))
    }
}
