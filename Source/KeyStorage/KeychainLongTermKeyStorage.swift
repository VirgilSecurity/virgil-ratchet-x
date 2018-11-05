//
//  KeychainLongTermKeyStorage.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 11/5/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSRKeychainLongTermKeysStorage) open class KeychainLongTermKeysStorage: NSObject, LongTermKeysStorage {
    private let keychainWrapper: KeychainStorageWrapper
    
    @objc public init(identity: String) throws {
        let params = try KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: params)
        self.keychainWrapper = KeychainStorageWrapper(identity: identity, prefix: "LTK", keychainStorage: keychainStorage)
        
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
        
        return LongTermKey(identifier: id, key: entry.data, creationDate: entry.creationDate, outdatedFrom: self.parseMeta(entry.meta))
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
        
        try self.keychainWrapper.updateEntry(withName: keyId.base64EncodedString(), data: entry.data, meta: self.makeMeta(outdated: date))
    }
}
