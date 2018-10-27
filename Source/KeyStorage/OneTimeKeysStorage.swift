//
//  OneTimeKeysStorage.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/27/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation
import VirgilSDK

@objc(VSROneTimeKey) public final class OneTimeKey: NSObject {
    @objc public let identifier: Data
    @objc public let key: Data
    @objc public let orphanedFrom: Date?
    
    @objc public init(identifier: Data, key: Data, orphanedFrom: Date?) {
        self.identifier = identifier
        self.key = key
        self.orphanedFrom = orphanedFrom
        
        super.init()
    }
}

@objc(VSROneTimeKeysStorage) public protocol OneTimeKeysStorage: class {
    @objc func startInteraction() throws
    @objc func stopInteraction() throws
    @objc func storeKey(_ key: Data, withId id: Data) throws -> OneTimeKey
    @objc func retrieveKey(withId id: Data) throws -> OneTimeKey
    @objc func deleteKey(withId id: Data) throws
    @objc func retrieveAllKeys() throws -> [OneTimeKey]
    @objc func markKeyOrphaned(startingFrom date: Date, keyId: Data) throws
}
