//
//  PrivateKeyProvider.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/19/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

@objc(VSRLongTermKey) public final class LongTermKey: NSObject {
    @objc public let identifier: Data
    @objc public let key: Data
    @objc public let creationDate: Date
    @objc public let outdatedFrom: Date?
    
    @objc public init(identifier: Data, key: Data, creationDate: Date, outdatedFrom: Date?) {
        self.identifier = identifier
        self.key = key
        self.creationDate = creationDate
        self.outdatedFrom = outdatedFrom
        
        super.init()
    }
}

@objc(VSRLongTermKeysStorage) public protocol LongTermKeysStorage: class {
    @objc func storeKey(_ key: Data, withId id: Data) throws -> LongTermKey
    @objc func retrieveKey(withId id: Data) throws -> LongTermKey
    @objc func deleteKey(withId id: Data) throws
    @objc func retrieveAllKeys() throws -> [LongTermKey]
    @objc func markKeyOutdated(startingFrom date: Date, keyId: Data) throws
}
